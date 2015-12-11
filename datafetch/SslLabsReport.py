import logging
import time

import requests
from bs4 import BeautifulSoup
from ghost import Ghost

WAIT_TIMEOUT_SECONDS = 10
SSL_LABS_URL = "https://www.ssllabs.com/ssltest/analyze.html?hideResults=on&d="
SSL_LABS_API_URL = "https://api.ssllabs.com/api/v2/analyze"
CHROME_USER_AGENT = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36"
SSLLABS_APPLE_MITM_MESSAGE = "Due to a recently discovered bug in Apple's code, your browser is exposed to MITM attacks"

logger = logging.getLogger("SslLabsReport")


class HostReport():
    def __init__(self, host, grade, grade_ignore_trust, errors, warnings, protocols, ciphers):
        self.host = host
        self.grade = grade
        self.grade_ignore_trust = grade_ignore_trust
        self.warnings = warnings
        self.errors = errors
        self.protocols = protocols
        self.ciphers = ciphers
        pass


def analyze_all(hosts):
    res = []
    for host in hosts:
        res.append(analyze(host))
    return res


def analyze(host):
    start_global = time.time()
    logger.info("Report requested for host %s", host)

    start = time.time()
    logger.info("[%s] Invoking rest api", host)
    grade, grade_trust_ignored, protocols, ciphers = _request_api_result(host)
    logger.info("[%s] Rest api result received in %.2f seconds. Grade: %s (%s) %s %s", host, time.time() - start, grade,
                grade_trust_ignored, str(protocols), str(ciphers))

    logger.info("[%s] requesting html page", host)
    markup = _get_html_page(host)
    # logger.debug("Html page: %s", str(markup))
    errors, warnings = _fetch_report(markup)
    logger.info("[%s] html page processed in %.2f seconds", host, time.time() - start)

    report = HostReport(host, grade, grade_trust_ignored, errors, warnings, protocols, ciphers)
    logger.info("[%s] report completed in %.2f seconds: %s (%s), %s, %s", host, time.time() - start_global, grade,
                grade_trust_ignored, str(errors), str(warnings))

    return report


def _wait_for_result(session, page):
    if page.http_status == 200:
        start = time.time()
        wait_success, text = session.wait_for_selector("#rating", WAIT_TIMEOUT_SECONDS)
        if wait_success:
            logger.info("Assessment data found in page in %.2f seconds", time.time() - start)
            return page.content
        else:
            raise Exception("Wait failure")
    else:
        raise Exception("Bad Response status %d", page.http_status)


def _get_html_page(host):
    ghost = Ghost()
    with ghost.start() as session:
        start = time.time()
        url = SSL_LABS_URL + host
        logger.debug("Request url: %s", url)
        page, extra_resources = session.open(
            url,
            headers={"User-Agent": CHROME_USER_AGENT},
            user_agent=CHROME_USER_AGENT,
            wait=True
        )
        logger.info("[%s] Html page retrieved in %.2f seconds,"
                    " starting wait for test completion", host, time.time() - start)
        return _wait_for_result(session, page)


def _fetch_report(html_markup):
    soup = BeautifulSoup(html_markup, 'html.parser')

    rating_el = soup.find_all("div", id="rating")[0]
    logger.debug("#rating el found: %s", str(rating_el))

    errors = soup.find_all("div", class_="errorBox")
    logger.debug("Errors found: %s", str(errors))
    errors = [er for er in errors if not er.text.strip().startswith(SSLLABS_APPLE_MITM_MESSAGE)]
    text_transform = lambda x: ' '.join(x.text.split())
    errors = map(text_transform, errors)
    logger.debug("Refined errors: %s", str(errors))

    warnings = soup.find_all("div", class_="warningBox")
    logger.debug("Warnings found: %s", str(warnings))
    warnings = map(text_transform, warnings)
    logger.debug("Refined warnings: %s", str(warnings))

    return errors, warnings


def _request_api_result(host, publish="off", startNew="off", all="done", ignoreMismatch="on"):
    payload = {'host': host, 'publish': publish, 'all': all, 'ignoreMismatch': ignoreMismatch}
    result = requests.get(SSL_LABS_API_URL, params=payload).json()

    if 'errors' in result:
        raise Exception("Incorrect api call: " + str(result))

    while result['status'] != 'READY' and result['status'] != 'ERROR':
        retry_interval_seconds = 30
        logger.info("[%s] Scan in progress, next check in %d seconds", host, retry_interval_seconds)
        time.sleep(retry_interval_seconds)
        result = requests.get(SSL_LABS_API_URL, params=payload).json()

    logger.debug("[%s] Result: %s", host, str(result))
    endpoint = result["endpoints"][0]
    return endpoint['grade'], endpoint['gradeTrustIgnored'], _protocols(endpoint), _ciphers(endpoint)


def _protocols(result):
    return map(lambda p: p['name'] + p['version'], result['details']['protocols'])


def _ciphers(result):
    return map(lambda p: p['name'], result['details']['suites']['list'])
