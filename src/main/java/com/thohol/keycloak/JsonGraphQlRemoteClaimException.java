package com.thohol.keycloak;

/**
 * @author <a href="mailto:ni.roussel@gmail.com">Nicolas Roussel</a>
 * @version $Revision: 1 $
 */
public class JsonGraphQlRemoteClaimException extends RuntimeException {

    public JsonGraphQlRemoteClaimException(String message, String url) {
        super(message + " - Configured URL: " + url);
    }

    public JsonGraphQlRemoteClaimException(String message, String url, Throwable cause) {
        super(message + " - Configured URL: " + url, cause);
    }

}