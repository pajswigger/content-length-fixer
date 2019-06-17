package burp

import java.net.URL

class BurpExtender: IBurpExtender {
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        callbacks.setExtensionName("Content Length Fixer")
        callbacks.registerHttpListener(HttpListener(callbacks))
    }
}


class HttpListener(val callbacks: IBurpExtenderCallbacks): IHttpListener {
    val CONTENT_LENGTH = "Content-Length"

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, requestResponse: IHttpRequestResponse) {
        if (!messageIsRequest) {
            return
        }

        val messageInfo = callbacks.helpers.analyzeRequest(requestResponse.httpService, requestResponse.request)
        val actualLength = requestResponse.request.size - messageInfo.bodyOffset

        for (i in messageInfo.headers.indices) {
            val header = messageInfo.headers[i]
            if (header.startsWith(CONTENT_LENGTH, ignoreCase = true)) {
                val contentLength = header.substring(CONTENT_LENGTH.length + 1).trim().toInt()
                if (contentLength != actualLength) {
                    val message = "Sent by tool: ${callbacks.getToolName(toolFlag)} Content-Length: $contentLength Actual Length: $actualLength"
                    callbacks.issueAlert("Request with incorrect Content-Length. $message")
                    callbacks.addScanIssue(ScanIssue(requestResponse.httpService,
                            message,
                            messageInfo.url,
                            arrayOf(requestResponse)))

                    val newHeaders = messageInfo.headers.toMutableList()
                    newHeaders[i] = "$CONTENT_LENGTH: $actualLength"
                    val body = requestResponse.request.copyOfRange(messageInfo.bodyOffset, requestResponse.request.size)
                    requestResponse.request = callbacks.helpers.buildHttpMessage(newHeaders, body)
                }
            }
        }
    }
}


class ScanIssue(
        override val httpService: IHttpService,
        override val issueDetail: String?,
        override val url: URL,
        override val httpMessages: Array<IHttpRequestResponse>): IScanIssue {
    override val confidence = "Certain"
    override val issueBackground = "Burp sent a request with an incorrect Content-Length header."
    override val issueName = "Incorrect Content-Length"
    override val issueType = 0x08000000
    override val remediationBackground: String? = null
    override val remediationDetail: String? = null
    override val severity = "Information"
}
