from burp import IBurpExtender
from burp import IHttpListener
import json
from java.net import URL, HttpURLConnection
from java.io import DataOutputStream
import threading

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Waymark Traffic Logger")
        callbacks.registerHttpListener(self)
        print("Waymark Traffic Logger loaded successfully.")
        print("Listening for traffic to forward to http://127.0.0.1:8000/api/v1/traffic/ingest")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We only process the response, because by then we have BOTH the request and response data!
        if messageIsRequest:
            return

        def send_to_waymark():
            try:
                request_info = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
                response_info = self._helpers.analyzeResponse(messageInfo.getResponse())

                url = str(request_info.getUrl())
                path = str(request_info.getUrl().getPath())
                method = str(request_info.getMethod())
                
                # Parse Request Headers
                req_headers = {}
                for header in request_info.getHeaders()[1:]:
                    parts = header.split(":", 1)
                    if len(parts) == 2:
                        req_headers[parts[0].strip()] = parts[1].strip()

                # Parse Response Headers
                res_headers = {}
                for header in response_info.getHeaders()[1:]:
                    parts = header.split(":", 1)
                    if len(parts) == 2:
                        res_headers[parts[0].strip()] = parts[1].strip()

                # Parse Bodies (Be careful with binary data, so we decode safely)
                req_body_offset = request_info.getBodyOffset()
                req_body = self._helpers.bytesToString(messageInfo.getRequest()[req_body_offset:]).encode('utf-8', 'ignore').decode('utf-8')

                res_body_offset = response_info.getBodyOffset()
                res_body = self._helpers.bytesToString(messageInfo.getResponse()[res_body_offset:]).encode('utf-8', 'ignore').decode('utf-8')

                payload = {
                    "method": method,
                    "url": url,
                    "path": path,
                    "query_params": {},
                    "request_headers": req_headers,
                    "request_body": req_body,
                    "response_status": response_info.getStatusCode(),
                    "response_headers": res_headers,
                    "response_body": res_body,
                    "source": "burp"
                }

                # Send POST request to Waymark backend
                target_url = URL("http://127.0.0.1:8000/api/v1/traffic/ingest")
                conn = target_url.openConnection()
                conn.setRequestMethod("POST")
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setDoOutput(True)

                out = DataOutputStream(conn.getOutputStream())
                out.writeBytes(json.dumps(payload))
                out.flush()
                out.close()

                conn.getResponseCode() # Trigger the request
            except Exception as e:
                print("Error sending traffic to Waymark: " + str(e))

        # Spin off a background thread so we don't slow down Burp's proxying!
        threading.Thread(target=send_to_waymark).start()
