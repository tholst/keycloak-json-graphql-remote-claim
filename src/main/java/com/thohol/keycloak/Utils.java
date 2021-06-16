package com.thohol.keycloak;

import org.jboss.logging.Logger;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

class Utils {
    private static final Logger LOGGER = Logger.getLogger(Utils.class);

    static Map<String, String> buildMapFromStringConfig(String config) {
        final Map<String, String> map = new HashMap<>();

        //FIXME: using MULTIVALUED_STRING_TYPE would be better but it doesn't seem to work
        if (config != null && !"".equals(config.trim())) {
            String[] configList = config.trim().split("&");
            String[] keyValue;
            for (String configEntry : configList) {
                keyValue = configEntry.split("=", 2);
                if (keyValue.length == 2) {
                    map.put(keyValue[0], keyValue[1]);
                }
            }
        }

        return map;
    }

    static String keyValConcat(Map<String, String> data, char kevValSep, char entrySep, String paddingSep, boolean urlEncode) {
        StringBuilder builder = new StringBuilder();
        data.forEach((key, value) -> {
            if (builder.length() > 0) {
                builder.append(entrySep);
            }
            builder.append(paddingSep);
            builder.append(urlEncode ? URLEncoder.encode(key, StandardCharsets.UTF_8) : key);
            builder.append(paddingSep);
            builder.append(kevValSep);
            builder.append(paddingSep);
            builder.append(urlEncode ? URLEncoder.encode(value, StandardCharsets.UTF_8) : value);
            builder.append(paddingSep);
        });
        return builder.toString();
    }

    static String getFormData(Map<String, String> data) {
        final String params = keyValConcat(data, '=', '&', "", true);
        LOGGER.debug("query params: " + params);
        return params;
    }

    static String getGraphQlBody(String query, Map<String, String> variables) {
        StringBuilder builder = new StringBuilder();
        builder.append("{\"query\":\"");
        builder.append(query);
        builder.append("\\n\",\"variables\":{");
        builder.append(keyValConcat(variables, ':', ',', "\"", false));
        builder.append("}}");
        LOGGER.debug("graphQL body: " + builder.toString());
        return builder.toString();
    }
}
