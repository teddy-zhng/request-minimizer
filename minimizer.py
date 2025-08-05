from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from burp import IParameter, IRequestInfo
from java.net import URL, URLClassLoader
from java.lang import Thread as JavaThread
from javax.swing import JMenuItem
import array

import xmltodict
from itertools import combinations

from threading import Thread
from functools import partial
import json
import time
import copy
import sys
import traceback

IGNORED_INVARIANTS = set(['last_modified_header'])

class Minimizer(object):
    def __init__(self, callbacks, request):
        self._cb = callbacks
        self._helpers = callbacks.helpers
        self._request = request[0]
        self._httpServ = self._request.getHttpService()
    
    def _fix_classloader_problems(self):
        # Get path to jython jar
        jython_jar = None
        for path in sys.path:
            if '.jar' in path and 'jython' in path.lower():
                jython_jar = path[:path.index('.jar')+4]
        if jython_jar is None:
            raise Exception("Could not locate jython jar in path!")
        classloader = URLClassLoader([URL("file://" + jython_jar)], JavaThread.currentThread().getContextClassLoader())
        JavaThread.currentThread().setContextClassLoader(classloader);

    def compare(self, etalon, response, etalon_invariant):
        invariant = set(self._helpers.analyzeResponseVariations([etalon, response]).getInvariantAttributes())
        print("Invariant", invariant)
        print("diff", set(etalon_invariant) - set(invariant))
        return len(set(etalon_invariant) - set(invariant)) == 0

    def minimize(self, replace, event):
        Thread(target=self._minimize, args=(replace,)).start()

    def _fix_cookies(self, current_req):
        """ Workaround for a bug in extender,
        see https://support.portswigger.net/customer/portal/questions/17091600
        """
        cur_request_info = self._helpers.analyzeRequest(current_req)
        new_headers = []
        rebuild = False
        for header in cur_request_info.getHeaders():
            if header.strip().lower() != 'cookie:':
                new_headers.append(header)
            else:
                rebuild = True
        if rebuild:
            return self._helpers.buildHttpMessage(new_headers, current_req[cur_request_info.getBodyOffset():])
        return current_req

    def removeHeader(self, req, target_header):
        req_info = self._helpers.analyzeRequest(req)
        new_headers = []
        headers = req_info.getHeaders()
        print("DEBUG: GetHeaders(): ", headers)
        for header in headers:
            if header != target_header :
                print("DEBUG: Header, target_Header", header, target_header)
                new_headers.append(header)
        return self._helpers.buildHttpMessage(new_headers, req[req_info.getBodyOffset():])
    
    def _remove_header_field(self, req, target_header, target_field):
        req_info = self._helpers.analyzeRequest(req)
        new_headers = []
        headers = req_info.getHeaders()
        for header in headers:
            if header.lower().startswith(target_header.lower()):
                header_parts = header.split(': ', 1)
                if len(header_parts) == 2:
                    header_name, header_value = header_parts
                    if target_header.lower() == 'cookie':
                        fields = [f for f in header_value.split('; ') if not f.strip().startswith(target_field + '=')]
                        if fields:
                            new_headers.append(header_name + ': ' + '; '.join(fields))
                        continue
            new_headers.append(header)
        return self._helpers.buildHttpMessage(new_headers, req[req_info.getBodyOffset():])

    def _minimize_cookies(self, etalon, invariants, initial_req):
        request_info = self._helpers.analyzeRequest(initial_req)
        
        cookie_params = [p for p in request_info.getParameters() if p.getType() == IParameter.PARAM_COOKIE]
        if not cookie_params:
            return initial_req

        original_cookie_header = [h for h in request_info.getHeaders() if h.lower().startswith('cookie:')]
        if not original_cookie_header:
            return initial_req

        cookie_fields = [c.strip() for c in original_cookie_header[0].split(':', 1)[1].split(';')]
        
        for i in range(1, len(cookie_fields) + 1):
            for combo in combinations(cookie_fields, i):
                new_cookie_value = '; '.join(combo)
                
                headers = [h for h in request_info.getHeaders() if not h.lower().startswith('cookie:')]
                if new_cookie_value:
                    headers.append("Cookie: " + new_cookie_value)

                new_req = self._helpers.buildHttpMessage(headers, initial_req[request_info.getBodyOffset():])

                resp = self._cb.makeHttpRequest(self._httpServ, new_req).getResponse()
                if self.compare(etalon, resp, invariants):
                    print("Found a working cookie set:", combo)
                    return new_req

        print("No minimal cookie set found. Falling back to the last working request.")
        return initial_req

    def _minimize(self, replace):
        try:
            self._fix_classloader_problems()
            seen_json = seen_xml = False
            request_info = self._helpers.analyzeRequest(self._request)
            current_req = self._request.getRequest()
            
            etalon = self._cb.makeHttpRequest(self._httpServ, current_req).getResponse()
            etalon2 = self._cb.makeHttpRequest(self._httpServ, current_req).getResponse()
            invariants = set(self._helpers.analyzeResponseVariations([etalon, etalon2]).getInvariantAttributes())
            invariants -= IGNORED_INVARIANTS
            print("Request invariants", invariants)

            temp_req = copy.copy(current_req)

            for param in list(request_info.getParameters()):
                param_type = param.getType()
                if param_type in [IParameter.PARAM_URL, IParameter.PARAM_BODY]:
                    print("Trying", param_type, param.getName(), param.getValue())
                    req_without_param = self._helpers.removeParameter(temp_req, param)
                    resp = self._cb.makeHttpRequest(self._httpServ, req_without_param).getResponse()
                    if self.compare(etalon, resp, invariants):
                        print("excluded:", param.getName())
                        temp_req = self._fix_cookies(req_without_param)
            
            request_info = self._helpers.analyzeRequest(temp_req)
            headers_to_check = [h for h in request_info.getHeaders()[2:] if not h.lower().startswith('cookie:')]
            for header in headers_to_check:
                req_without_header = self.removeHeader(temp_req, header)
                resp = self._cb.makeHttpRequest(self._httpServ, req_without_header).getResponse()
                if self.compare(etalon, resp, invariants):
                    print("excluded: Header ", header)
                    temp_req = self._fix_cookies(req_without_header)

            current_req = self._minimize_cookies(etalon, invariants, temp_req)
            request_info = self._helpers.analyzeRequest(current_req)
            
            seen_json = (request_info.getContentType() == IRequestInfo.CONTENT_TYPE_JSON or any(p.getType() == IParameter.PARAM_JSON for p in request_info.getParameters()))
            seen_xml = (request_info.getContentType() == IRequestInfo.CONTENT_TYPE_XML or any(p.getType() == IParameter.PARAM_XML for p in request_info.getParameters()))

            if seen_json or seen_xml:
                body_offset = request_info.getBodyOffset()
                headers = self._helpers.bytesToString(current_req[:body_offset])
                body = self._helpers.bytesToString(current_req[body_offset:])

                if seen_json:
                    print('Minimizing json...')
                    dumpmethod = partial(json.dumps, indent=4)
                    loadmethod = json.loads
                elif seen_xml:
                    print('Minimizing XML...')
                    dumpmethod = partial(xmltodict.unparse, pretty=True)
                    loadmethod = xmltodict.parse
                
                def check(body_data):
                    if isinstance(body_data, dict) and not body_data and not seen_json:
                        return False
                    
                    try:
                        serialized_body = dumpmethod(body_data)
                        req = fix_content_type(headers, serialized_body)
                        resp = self._cb.makeHttpRequest(self._httpServ, req).getResponse()
                        return self.compare(etalon, resp, invariants)
                    except Exception as e:
                        print("Error during check:", e)
                        return False

                body_data = loadmethod(body)
                body_data = bf_search(body_data, check)
                current_req = fix_content_type(headers, dumpmethod(body_data))
            
            if replace:
                self._request.setRequest(current_req)
            else:
                self._cb.sendToRepeater(
                    self._httpServ.getHost(),
                    self._httpServ.getPort(),
                    self._httpServ.getProtocol() == 'https',
                    current_req,
                    "minimized"
                )
        except:
            print traceback.format_exc()

def bf_search(body, check_func):
    print('Starting to minimize', body)
    if isinstance(body, dict):
        to_test = list(body.items())
    elif type(body) == list:
        to_test = list(zip(range(len(body)), body))
        
    tested = []
    while len(to_test):
        current_key, current_value = to_test.pop()
        
        test_body = copy.deepcopy(body)
        if isinstance(body, dict):
            del test_body[current_key]
        elif isinstance(body, list):
            del test_body[current_key]
        
        if check_func(test_body):
            print('Successfully eliminated', current_key)
            body = test_body
            to_test = [(k, v) for k, v in to_test if (k != current_key if isinstance(body, dict) else k != current_key)]
        else:
            print('Could not eliminate', current_key)
            tested.append((current_key, current_value))

    if isinstance(body, dict):
        for key in list(body.keys()):
            value = body[key]
            if isinstance(value, (list, dict)):
                def check_func_rec(new_value):
                    test_body = copy.deepcopy(body)
                    test_body[key] = new_value
                    return check_func(test_body)
                body[key] = bf_search(value, check_func_rec)
    elif isinstance(body, list):
        for i in range(len(body)):
            value = body[i]
            if isinstance(value, (list, dict)):
                def check_func_rec(new_value):
                    test_body = copy.deepcopy(body)
                    test_body[i] = new_value
                    return check_func(test_body)
                body[i] = bf_search(value, check_func_rec)

    return body

def fix_content_type(headers, body):
    headers = headers.split('\r\n')
    new_headers = []
    body_bytes = body.encode('utf-8')
    for header in headers:
        if header.lower().startswith('content-length'):
            new_headers.append('Content-Length: ' + str(len(body_bytes)))
        else:
            new_headers.append(header)
    return array.array('b', '\r\n'.join(new_headers) + '\r\n\r\n' + body_bytes)

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Request minimizer")
        callbacks.registerContextMenuFactory(self)
        self._callbacks = callbacks

    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            return [JMenuItem(
                        "Minimize in current tab",
                        actionPerformed=partial(
                            Minimizer(self._callbacks, invocation.getSelectedMessages()).minimize,
                            True
                        )
                    ),
                    JMenuItem(
                        "Minimize in a new tab",
                        actionPerformed=partial(
                            Minimizer(self._callbacks, invocation.getSelectedMessages()).minimize,
                            False
                        )
                    ),
            ]