package com.thohol.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.apache.http.HttpHeaders;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

class HttpHandler {
    private static final Logger LOGGER = Logger.getLogger(HttpHandler.class);
    private static final OkHttpClient okHttpClient = new OkHttpClient.Builder()
            .retryOnConnectionFailure(true)
            .build();

    private static final OkHttpClient retryOkHttpClient = new OkHttpClient.Builder()
            .retryOnConnectionFailure(true)
            .addInterceptor(retryInterceptor())
            .build();

    static JsonNode getJsonNode(boolean retryEnabled, String baseUrl, String contentType, Map<String, String> headers, Map<String, String> queryParameters, Map<String, String> formParameters, String graphQlQuery) {
        LOGGER.info("Started processing request, url: " + baseUrl);
        try {
            Request request;
            if (isGraphQlQuery(graphQlQuery)) {
                request = prepareGraphQLRequest(baseUrl, contentType, headers, queryParameters, graphQlQuery);
            } else {
                request = prepareAuthenticationRequest(baseUrl, contentType, headers, queryParameters, formParameters);
            }

            Call call;
            if (retryEnabled) {
                call = retryOkHttpClient.newCall(request);
            } else {
                call = okHttpClient.newCall(request);
            }

            try (Response response = call.execute()) {
                if (!response.isSuccessful()) {
                    LOGGER.error("ERROR Response status: " + response.code() + " url: " + baseUrl);
                    LOGGER.error("ERROR Response body: " + response.body().string());

                    throw new JsonGraphQlRemoteClaimException("Wrong status received for remote claim - Expected: 200, Received: " + response.code(), baseUrl);
                }

                String responseBody = Objects.requireNonNull(response.body().string());
                return new ObjectMapper().readTree(responseBody);
            }
        } catch (IOException e) {
            throw new JsonGraphQlRemoteClaimException("Error when parsing response for remote claim", baseUrl, e);
        }
    }

    private static Request prepareAuthenticationRequest(String baseUrl, String contentType, Map<String, String> headers, Map<String, String> queryParameters, Map<String, String> formParameters) {
        try {
            headers.put(HttpHeaders.CONTENT_TYPE, contentType);
            Headers requestHeaders = Headers.of(headers);

            Request.Builder builder = new Request.Builder()
                    .cacheControl(CacheControl.FORCE_NETWORK)
                    .url(Objects.requireNonNull(HttpUrl.parse(baseUrl)))
                    .headers(requestHeaders);

            if (formParameters != null) {
                builder.post(RequestBody.create(
                        MediaType.parse("Content-Type: application/x-www-form-urlencoded"),
                        Utils.getFormData(formParameters))
                );
            }

            return builder.build();
        } catch (Exception e) {
            throw new JsonGraphQlRemoteClaimException("Error when preparing Authentication request", baseUrl, e);
        }
    }

    private static Request prepareGraphQLRequest(String baseUrl, String contentType, Map<String, String> headers, Map<String, String> queryParameters, String graphQlQuery) {
        try {
            headers.put(HttpHeaders.CONTENT_TYPE, contentType);
            Headers requestHeaders = Headers.of(headers);

            String graphQlBody = Utils.getGraphQlBody(graphQlQuery, queryParameters);

            return new Request.Builder()
                    .post(RequestBody.create(MediaType.parse(contentType), graphQlBody))
                    .cacheControl(CacheControl.FORCE_NETWORK)
                    .url(baseUrl)
                    .headers(requestHeaders)
                    .build();

        } catch (Exception e) {
            throw new JsonGraphQlRemoteClaimException("Error when preparing GraphQL request", baseUrl, e);
        }
    }

    private static boolean isGraphQlQuery(String graphQlQuery) {
        return graphQlQuery != null;
    }

    private static Interceptor retryInterceptor() {
        return chain -> {
            var retryCount = 2;
            Response response;
            Request request = chain.request();
            response = chain.proceed(request);

            int tryCount = 1;
            while (!response.isSuccessful() && tryCount <= retryCount) {
                response.close();
                LOGGER.warn("Request is not successful - attempt: " + tryCount);
                tryCount++;
                response = chain.proceed(request);
            }
            return response;
        };
    }
}
