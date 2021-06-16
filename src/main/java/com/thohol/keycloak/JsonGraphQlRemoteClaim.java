package com.thohol.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.HttpHeaders;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.MediaType;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:ni.roussel@gmail.com">Nicolas Roussel</a>
 * @author <a href="mailto:thomas@thohol.com">Thomas Holst</a>
 */
public class JsonGraphQlRemoteClaim extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    /*
     * ID of the token mapper.
     * Must be public
     */
    public final static String PROVIDER_ID = "json-remote-claim";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final Logger LOGGER = Logger.getLogger(JsonGraphQlRemoteClaim.class);
    private final static String DEBUG_ERRORS_RETURN = "debugging.errors.catchall";
    private final static String DEBUG_ERRORS_SUPPRESS = "debugging.errors.suppress";
    private final static String DEBUG_REMOTE_DISABLED = "debugging.remote.disabled";
    private final static String REMOTE_URL = "remote.url";
    private final static String REMOTE_HEADERS = "remote.headers";
    private final static String REMOTE_PARAMETERS = "remote.parameters";
    private final static String REMOTE_PARAMETERS_USERNAME = "remote.parameters.username";
    private final static String REMOTE_PARAMETERS_CLIENTID = "remote.parameters.clientid";
    private static final String REMOTE_PARAMETERS_USER_ATTRIBUTES = "remote.parameters.user.attributes";
    private static final String REMOTE_HEADERS_BEARER_TOKEN = "remote.headers.bearer.token";
    private static final String CLIENT_AUTH_URL = "client.auth.url";
    private static final String CLIENT_AUTH_ID = "client.auth.id";
    private static final String CLIENT_AUTH_PASS = "client.auth.pass";
    private final static String REMOTE_GRAPHQL = "remote.graphql";
    private final static String REMOTE_GRAPHQL_QUERY = "remote.graphql.query";
    private final static String REMOTE_GRAPHQL_RESULT_PATH = "remote.graphql.path";
    private final static String RETRY_REQUEST = "retry.request";
    /**
     * Inner configuration to cache retrieved authorization for multiple tokens
     */
    private final static String REMOTE_AUTHORIZATION_ATTR = "remote-authorizations";

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, JsonGraphQlRemoteClaim.class);
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty property;

        // Disable
        property = new ProviderConfigProperty();
        property.setName(DEBUG_REMOTE_DISABLED);
        property.setLabel("Disable Remote Requests (Debugging)");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Disable all remote requests. For debugging. Will set claim value to \"disabled\".");
        configProperties.add(property);

        // Suppress Errors
        property = new ProviderConfigProperty();
        property.setName(DEBUG_ERRORS_SUPPRESS);
        property.setLabel("Suppress all Errors");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Catches all errors (e.g., 500 response status). Will set claim value to \"error\" in case of error.");
        configProperties.add(property);

        // Return Errors
        property = new ProviderConfigProperty();
        property.setName(DEBUG_ERRORS_RETURN);
        property.setLabel("Return all Errors (Debugging)");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Catches all errors (e.g., 500 response status) and returns them as part of the token. For debugging. Will set claim value to error message. This setting overrules \"Suppress all Errors\".");
        configProperties.add(property);

        // Username
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_USERNAME);
        property.setLabel("Send User Name");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the username as query parameter (param: username).");
        property.setDefaultValue("true");
        configProperties.add(property);

        // Client_id
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_CLIENTID);
        property.setLabel("Send Client ID");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the client_id as query parameter (param: client_id).");
        property.setDefaultValue("false");
        configProperties.add(property);

        // User attributes
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_USER_ATTRIBUTES);
        property.setLabel("User attributes");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Send custom user attributes as query parameter. Separate value by '&' sign.");
        configProperties.add(property);

        // URL
        property = new ProviderConfigProperty();
        property.setName(REMOTE_URL);
        property.setLabel("URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Full URL of the remote service endpoint.");
        configProperties.add(property);

        // Parameters
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS);
        property.setLabel("Parameters");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of query parameters to send separated by '&'. Separate parameter name and value by an equals sign '=', the value can contain equals signs (ex: scope=all&full=true).");
        configProperties.add(property);

        // Headers
        property = new ProviderConfigProperty();
        property.setName(REMOTE_HEADERS);
        property.setLabel("Headers");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of headers to send separated by '&'. Separate header name and value by an equals sign '=', the value can contain equals signs (ex: Authorization=az89d).");
        configProperties.add(property);

        // Bearer token
        property = new ProviderConfigProperty();
        property.setName(REMOTE_HEADERS_BEARER_TOKEN);
        property.setLabel("Send Bearer Token");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the bearer token as auth header.");
        configProperties.add(property);

        // Client auth url
        property = new ProviderConfigProperty();
        property.setName(CLIENT_AUTH_URL);
        property.setLabel("Client Auth URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Full URL of the keycloak client auth endpoint.");
        configProperties.add(property);

        // Client id
        property = new ProviderConfigProperty();
        property.setName(CLIENT_AUTH_ID);
        property.setLabel("Client ID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Client id to create a tech token.");
        configProperties.add(property);

        // Client password
        property = new ProviderConfigProperty();
        property.setName(CLIENT_AUTH_PASS);
        property.setLabel("Client Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Client secret to create a tech token for access to the remote service.");
        configProperties.add(property);

        // Bearer token
        property = new ProviderConfigProperty();
        property.setName(REMOTE_GRAPHQL);
        property.setLabel("Send a GraphQL Query");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send a GraphQL query in a POST request.");
        configProperties.add(property);

        // GraphQL query
        property = new ProviderConfigProperty();
        property.setName(REMOTE_GRAPHQL_QUERY);
        property.setLabel("GraphQL Query");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("GraphQL query as escaped string. The query can only use variables 'username' and 'client_id' (if enabled above)");
        configProperties.add(property);

        // Client auth url
        property = new ProviderConfigProperty();
        property.setName(REMOTE_GRAPHQL_RESULT_PATH);
        property.setLabel("GraphQL Query Result Path");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("The JSON path of the result data that should be assigned to the custom claim.");
        configProperties.add(property);

        // Retry mechanism
        property = new ProviderConfigProperty();
        property.setName(RETRY_REQUEST);
        property.setLabel("Retry Request");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue("false");
        property.setHelpText("Retry request when it fails");
        configProperties.add(property);
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getDisplayType() {
        return "JSON GraphQL Remote Claim";
    }

    @Override
    public String getHelpText() {
        return "Retrieve JSON data to include from a remote authenticated HTTP/GraphQL endpoint.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    protected void _setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        final boolean disabled = "true".equals(mappingModel.getConfig().get(DEBUG_REMOTE_DISABLED));
        JsonNode claims = clientSessionCtx.getAttribute(REMOTE_AUTHORIZATION_ATTR, JsonNode.class);
        if (claims == null && !disabled) {
            claims = getRemoteAuthorizations(mappingModel, userSession, clientSessionCtx);
            clientSessionCtx.setAttribute(REMOTE_AUTHORIZATION_ATTR, claims);
        }

        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, (claims == null && disabled) ? "disabled" : claims);
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        final boolean returnErrors = "true".equals(mappingModel.getConfig().get(DEBUG_ERRORS_RETURN));
        final boolean suppressErrors = "true".equals(mappingModel.getConfig().get(DEBUG_ERRORS_SUPPRESS));
        if (returnErrors || suppressErrors) {
            try {
                _setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
            } catch (Throwable t) {
                OIDCAttributeMapperHelper.mapClaim(token, mappingModel, returnErrors ? t.toString() : "error");
            }
        } else {
            _setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
        }
    }

    protected void _setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        final boolean disabled = "true".equals(mappingModel.getConfig().get(DEBUG_REMOTE_DISABLED));
        if (disabled) {
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, "disabled");
        } else {
            JsonNode claims = getRemoteAuthorizations(mappingModel, userSession, null);
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claims);
        }
    }

    /**
     * Deprecated, added for older versions
     * <p>
     * Caution: This version does not allow to minimize request number
     *
     * @deprecated override {@link #setClaim(IDToken, ProtocolMapperModel, UserSessionModel, KeycloakSession, ClientSessionContext)} instead.
     */
    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        final boolean returnErrors = "true".equals(mappingModel.getConfig().get(DEBUG_ERRORS_RETURN));
        final boolean suppressErrors = "true".equals(mappingModel.getConfig().get(DEBUG_ERRORS_SUPPRESS));
        if (returnErrors || suppressErrors) {
            try {
                _setClaim(token, mappingModel, userSession);
            } catch (Throwable t) {
                OIDCAttributeMapperHelper.mapClaim(token, mappingModel, returnErrors ? t.toString() : "error");
            }
        } else {
            _setClaim(token, mappingModel, userSession);
        }
    }

    private Map<String, String> getQueryParameters(ProtocolMapperModel mappingModel, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        final String configuredParameter = mappingModel.getConfig().get(REMOTE_PARAMETERS);
        final boolean sendUsername = "true".equals(mappingModel.getConfig().get(REMOTE_PARAMETERS_USERNAME));
        final boolean sendClientID = "true".equals(mappingModel.getConfig().get(REMOTE_PARAMETERS_CLIENTID));
        final String configuredUserAttributes = mappingModel.getConfig().get(REMOTE_PARAMETERS_USER_ATTRIBUTES);

        // Get parameters
        final Map<String, String> formattedParameters = Utils.buildMapFromStringConfig(configuredParameter);

        // Get client ID
        if (sendClientID) {
            if (clientSessionCtx != null) {
                formattedParameters.put("client_id", clientSessionCtx.getClientSession().getClient().getId());
            } else {
                formattedParameters.put("client_id", userSession.getAuthenticatedClientSessions().values().stream()
                        .map(AuthenticatedClientSessionModel::getClient)
                        .map(ClientModel::getClientId)
                        .distinct()
                        .collect(Collectors.joining(",")));
            }
        }

        // Get username
        if (sendUsername) {
            // username is passed as lower case for consistency because keycloak does the same internally
            final String userName = userSession.getLoginUsername().toLowerCase();
            final String variableName = "username";
            formattedParameters.put(variableName, userName);
        }

        // Get custom user attributes
        if (configuredUserAttributes != null && !"".equals(configuredUserAttributes.trim())) {
            List<String> userAttributes = Arrays.asList(configuredUserAttributes.trim().split("&"));
            userAttributes.forEach(attribute -> formattedParameters.put(attribute, userSession.getUser().getFirstAttribute(attribute)));
        }
        return formattedParameters;
    }

    private Map<String, String> getheaders(ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        final String configuredHeaders = mappingModel.getConfig().get(REMOTE_HEADERS);
        final boolean sendBearerToken = "true".equals(mappingModel.getConfig().get(REMOTE_HEADERS_BEARER_TOKEN));

        // Get headers
        Map<String, String> stringStringMap = Utils.buildMapFromStringConfig(configuredHeaders);
        if (sendBearerToken) {
            String signedRequestToken = getClientToken(mappingModel);
            stringStringMap.put(HttpHeaders.AUTHORIZATION, "Bearer " + signedRequestToken);
        }
        return stringStringMap;
    }

    private String getClientToken(ProtocolMapperModel mappingModel) {
        // Get parameters
        Map<String, String> parameters = new HashMap<>();
        // Get headers
        Map<String, String> headers = new HashMap<>();

        Map<String, String> formParameters = new HashMap<>();
        formParameters.put("grant_type", "client_credentials");
        formParameters.put("client_id", mappingModel.getConfig().get(CLIENT_AUTH_ID));
        formParameters.put("client_secret", mappingModel.getConfig().get(CLIENT_AUTH_PASS));

        // Call remote service
        String baseUrl = mappingModel.getConfig().get(CLIENT_AUTH_URL);
        boolean retryEnabled = "true".equals(mappingModel.getConfig().get(RETRY_REQUEST));

        JsonNode jsonNode = HttpHandler.getJsonNode(retryEnabled, baseUrl, MediaType.APPLICATION_FORM_URLENCODED, headers, parameters, formParameters, null);
        if (!jsonNode.has("access_token")) {
            throw new JsonGraphQlRemoteClaimException("Access token not found", baseUrl);
        }
        return jsonNode.findValue("access_token").asText();
    }

    private JsonNode getRemoteAuthorizations(ProtocolMapperModel mappingModel, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        final boolean sendGraphQL = "true".equals(mappingModel.getConfig().get(REMOTE_GRAPHQL));
        final String graphQlQuery = mappingModel.getConfig().get(REMOTE_GRAPHQL_QUERY);
        final String graphQlQueryResultPath = mappingModel.getConfig().get(REMOTE_GRAPHQL_RESULT_PATH);
        // Get parameters
        Map<String, String> parameters = getQueryParameters(mappingModel, userSession, clientSessionCtx);
        // Get headers
        Map<String, String> headers = getheaders(mappingModel, userSession);

        // Call remote service
        String baseUrl = mappingModel.getConfig().get(REMOTE_URL);
        boolean retryEnabled = "true".equals(mappingModel.getConfig().get(RETRY_REQUEST));
        if (sendGraphQL) {
            JsonNode result = HttpHandler.getJsonNode(retryEnabled, baseUrl, MediaType.APPLICATION_JSON, headers, parameters, null, graphQlQuery);

            // select desired data from result json object
            if (graphQlQueryResultPath != null && !"".equals(graphQlQueryResultPath.trim())) {
                List<String> pathSegments = Arrays.asList(graphQlQueryResultPath.trim().split("\\."));
                for (String pathSegment : pathSegments) {
                    if (result != null)
                        result = result.path(pathSegment);
                }
            }

            return result;
        } else {
            return HttpHandler.getJsonNode(retryEnabled, baseUrl, MediaType.APPLICATION_JSON, headers, parameters, null, null);
        }
    }
}
