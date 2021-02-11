"""
Copyright (c) 2020. Nico Hein

A cloud function to create and update a firewall rule that allows all VMs in a network
to reach all google services but not those from google cloud customers.

According to [Google Suport]](https://support.google.com/a/answer/10026322?hl=en)
there are two endpoints from google. One is providing information about all IP ranges announced by google and
one with all ranges used by google could customers.

"""

import requests
import logging
import json
import base64
import time
import yaml
from netaddr import IPSet


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

logging.basicConfig(level=logging.INFO, format='%(message)s')


def header(token):
    """
    returns a generic header used for insert and update Deployment manader API calls.
    :param token: bearer token
    :return: header dict as expected by requests
    """
    return {
        'Metadata-Flavor': 'Google',
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }


def update_deployment(project, deployment, body, token):
    """
    Updates a Google Deployment Manager deployment.

    :param project: Google Cloud Platform project name
    :param deployment: Google Deployment Manager deployment name
    :param body: as defined in https://cloud.google.com/deployment-manager/docs/reference/latest/deployments/update
    :param token: bearer token
    :return: parsed API response body
    """
    url = f'https://www.googleapis.com/deploymentmanager/v2/projects/{project}/global/deployments/{deployment}'

    payload = {
        'createPolicy': 'CREATE_OR_ACQUIRE'
    }

    response = requests.put(url=url, headers=header(token), params=payload, data=body)
    logger.debug(response.text)
    response.raise_for_status()

    return response.json()


def insert_deployment(project, body, token):
    """
    Inserts a Google Deployment Manager deployment.

    :param project: Google Cloud Platform project name
    :param body: as defined in https://cloud.google.com/deployment-manager/docs/reference/latest/deployments/insert
    :param token: bearer token
    :return: parsed API response body
    """
    url = f'https://www.googleapis.com/deploymentmanager/v2/projects/{project}/global/deployments'

    payload = {
        'createPolicy': 'CREATE_OR_ACQUIRE'
    }

    response = requests.post(url=url, headers=header(token), params=payload, data=body)

    logger.debug(response.text)
    response.raise_for_status()

    return response.json()


def get_deployment(project, deployment, token):
    """
    Gets a Google Deployment Manager deployment as documented
    https://cloud.google.com/deployment-manager/docs/reference/latest/deployments/get

    :param project: Google Cloud Platform project name
    :param deployment: Google Deployment Manager deployment name
    :param token: bearer token
    :return: parsed API response body
    """
    url = f'https://www.googleapis.com/deploymentmanager/v2/projects/{project}/global/deployments/{deployment}'

    response = requests.get(url=url, headers=header(token))

    logger.debug(response.text)

    if response.status_code == 404:
        return None

    # raise if error is different from 404 (assuming url formatting is correct)
    response.raise_for_status()
    return response.json()


def create_or_update_deployment(project, deployment, manifest, token, timeout=600):
    """
    Synchronous function that created or updates a Google Deployment Manager deployment.
    At first it is checked if the deployment exists. If it does an update is triggered.
    If it does not exist it's creation is triggered.
    Then the function waits until ither the timeout limit is hit or the deployment status changes
    to DONE.

    :param project: Google Cloud Platform project name
    :param deployment: Google Deployment Manager deployment name
    :param manifest: Google Deployment Manager manifest
    :param token: bearer token
    :param timeout: Maximal wait time for a deployment status change to DONE.
    :return: return value of Google deployment manager API call to get the FW rule deployment
    """
    # we first need to get, then decide if insert or update

    deployment_resource = dict(target=dict(config=dict()))
    deployment_resource['target']["config"]['content'] = manifest
    deployment_resource['name'] = deployment

    existing_deployment = get_deployment(project, deployment, token)

    if existing_deployment:
        # we need to update
        deployment_resource['fingerprint'] = existing_deployment['fingerprint']
        logger.info(f"Updating deployment {deployment}")
        update_deployment(project, deployment, json.dumps(deployment_resource), token)
    else:
        logger.info(f"Creating deployment {deployment}")
        insert_deployment(project, json.dumps(deployment_resource), token)

    # while loop until timeout
    timeout_time = time.time() + timeout  # a max timeout of 10min

    updated_deployment = get_deployment(project, deployment, token)
    while time.time() < timeout_time:
        time.sleep(5)
        logger.info('Waiting for resource creation...')
        if updated_deployment['operation']['status'] == "DONE":  # PENDING , RUNNING
            # check for error
            logger.info("Operation status changed to DONE")
            if 'error' in updated_deployment['operation']:
                logger.error(json.dumps(updated_deployment['operation']['error']))
                raise Exception(json.dumps(updated_deployment['operation']['error']))
            # if its it done and there is no error exit
            break
        updated_deployment = get_deployment(project, deployment, token)

    if updated_deployment['operation']['status'] != "DONE":
        logger.warning("Timed out waiting for deployment manager to finish...")

    return updated_deployment


def collect_ip_ranges(url):
    """
    Extracting IP ranges from given Google API endpoints.

    :param url: API endpoint
    :return: list of ipv4 cidr blocks returned by the API
    """
    ranges = []
    # this request should only fail if gstatic was moved to a new range that is not part of the FW rule yet
    response = requests.get(url)
    response.raise_for_status()
    json_response = response.json()
    # let python handle key errors of unexpected response formats when possible
    for prefix in json_response["prefixes"]:
        if "ipv4Prefix" in prefix:
            ranges.append(prefix["ipv4Prefix"])
        elif "ipv6Prefix" in prefix:
            # ignore ipv6 for now as it is not supported by google vpcs
            # https://cloud.google.com/vpc/docs/vpc#specifications
            # ranges.append(prefix["ipv6Prefix"])
            pass
        else:
            raise KeyError("Neither ipv4Prefix nor ipv6Prefix found in prefix. Unexpected response format.")
    return ranges


def generate_fw_template(destination_ranges, project, network, firewall_rule_name, firewall_rule_description):
    """
    Generates a firewall rule manifest.

    :param destination_ranges: Destination ipv4 CIDR ranges
    :param project: Google Cloud Platform project name
    :param network: Google Cloud network name
    :param firewall_rule_name: firewall rule name
    :param firewall_rule_description: custom firewall rule description to be appended to the default description
    :return: dumped yaml string of the manifest
    """
    firewall = {
        "resources": [{
            "name": firewall_rule_name,
            "type": "compute.v1.firewall",
            "properties": {
               "network": f"projects/{project}/global/networks/{network}",
               "direction": "EGRESS",
               "priority": 65530,
               "description": f"Allowing VMs to reach all Google services based on a difference-set of "
                              f"https://www.gstatic.com/ipranges/cloud.json and goog.json. "
                              f"{firewall_rule_description}",
               "allowed": [{
                   "IPProtocol": "tcp",
                   "ports": [80, 443, 8080]
               }],
               "targetTags": ["allow-egress-google-services"]
            }
        }]
    }

    firewall['resources'][0]['properties']['destinationRanges'] = destination_ranges
    return yaml.dump(firewall, default_flow_style=False)


def get_identity_token(scopes='https://www.googleapis.com/auth/cloud-platform'):
    """
    Getting an identity token from a google authorization service.

    :param scopes: https://cloud.google.com/deployment-manager/docs/reference/latest/authorization
    :return: bearer token
    """
    host = 'http://metadata.google.internal'
    url = f'{host}/computeMetadata/v1/instance/service-accounts/default/token?scopes={scopes}'

    response = requests.get(url=url, headers={'Metadata-Flavor': 'Google'})
    response.raise_for_status()
    # we are always quicker than the lifetime of the token an therefore skip checking expired_in and token_type
    return response.json()['access_token']


def update_firewall(project, network, firewall_rule_name, firewall_rule_description):
    """
    Generic function to update the firewall that resultes either in an inserted or an updated Firewall rule.
    This function takes care of authorization, collecting the list if required CIDR blocks and the FW rule deployment.

    :param project: Google Cloud Platform project name
    :param network: Google Cloud network name
    :param firewall_rule_name: firewall rule name
    :param firewall_rule_description: custom firewall rule description to be appended to the default description
    :return: return value of Google deployment manager API call to get the FW rule deployment
    """
    # urls from https://support.google.com/a/answer/10026322?hl=en
    google_ranges = collect_ip_ranges("https://www.gstatic.com/ipranges/goog.json")
    google_cloud_customer_ranges = collect_ip_ranges("https://www.gstatic.com/ipranges/cloud.json")

    # set token manually to test
    token = get_identity_token()

    diffset = IPSet(google_ranges).difference(IPSet(google_cloud_customer_ranges)).iter_cidrs()
    google_service_ranges = [str(cidr) for cidr in diffset]

    # checking feasability of result with heuristic
    if len(google_service_ranges) > 200 or len(google_service_ranges) < 10:
        raise Exception(f"Unexpected amount of service ranges ({len(google_service_ranges)}). "
                        f"Requires manual review: {google_service_ranges}")

    manifest = generate_fw_template(
        google_service_ranges,
        project,
        network,
        firewall_rule_name,
        firewall_rule_description)

    return create_or_update_deployment(project, firewall_rule_name, manifest, token)


def http_main(request):
    """
    Method to be invoked by a http type cloud function.

    :param request: flask request
    :return: return value of Google deployment manager API call to get the FW rule deployment
    """
    if not request:
        raise ValueError("request must be provided")

    request_json = request.get_json(silent=True)
    request_args = request.args

    def extract_argument(key, request_payload, request_args):
        """
        Extracting a value from request payload or arguments with a priority to the payload.

        :param key: name of the key to be extracted
        :param request_payload: payload or body of the request
        :param request_args: arguments or parameters of the request
        :return: value corresponding to the given key
        """
        if request_payload and key in request_payload:
            return request_payload[key]
        elif request_args and key in request_args:
            return request_args[key]
        else:
            raise ValueError(f"Expected {key} either in request payload or request arguments.")

    project = extract_argument("project", request_json, request_args)
    # maybe it makes sense to allow all relevant fw rule properties in a sub dict
    network = extract_argument("network", request_json, request_args)
    firewall_rule_name = extract_argument("firewall_rule_name", request_json, request_args)
    firewall_rule_description = extract_argument("firewall_rule_description", request_json, request_args)

    return update_firewall(
        project,
        network,
        firewall_rule_name,
        firewall_rule_description
    )


def pubsub_main(message, origin):
    """
    Method to be invoked by a PubSub cloud function.

    :param message: pubsub message argument
    :param origin: pubsub origin argument
    :return: return value of Google deployment manager API call to get the FW rule deployment
    """
    # no error handling as python errors are sufficient
    data = json.loads(base64.b64decode(message['data']))

    return update_firewall(
        data['project'],
        data['network'],
        data['firewall_rule_name'],
        data['firewall_rule_description']
    )
