package org.wso2.carbon.identity.conditional.auth.functions.elk.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class ElasticConfigProvider {

    private static final String CONFIG_PATH = "queries/risk_profile_query.json";
    private static final String ES_QUERY_PARAM_USERNAME = "[ES_QUERY_PARAM_USERNAME]";
    private static final String ES_QUERY_PARAM_DURATION = "[ES_QUERY_PARAM_DURATION]";
    private static final String ES_QUERY_PARAM_DURATION_DEFAULT = "5m";
    private static final String ES_QUERY_PARAM_LOGIC = "[ES_QUERY_PARAM_LOGIC]";
    private static final String ES_QUERY_PARAM_LOGIC_DEFAULT = "state.sum.add(doc['amount'].value);";
    private static final String ES_QUERY_PARAM_THRESHOLD = "[ES_QUERY_PARAM_THRESHOLD]";
    private static final String ES_QUERY_PARAM_THRESHOLD_DEFAULT = "10000";
    private static final String ES_INDEX_DEFAULT = "transaction";


    private static final ElasticConfigProvider instance = new ElasticConfigProvider();

    private ElasticConfigProvider() {

    }

    public static ElasticConfigProvider getInstance() {

        return instance;
    }

    private String readConfigFile() throws IOException {
        String fileContent;

        InputStream is = getClass().getClassLoader().getResourceAsStream(CONFIG_PATH);

        if (is == null) {
            fileContent = "FILE READ FAILED";
        } else {
            InputStreamReader isReader = new InputStreamReader(is);
            BufferedReader reader = new BufferedReader(isReader);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            fileContent = sb.toString();
        }

        return fileContent;
    }

    public String getElasticSearchUrl(String elasticDomain, Map<String, String> params) {
        return elasticDomain + params.getOrDefault("index", ES_INDEX_DEFAULT) + "/_search?size=0";
    }

    public String getQuery(Map<String, String> params) throws IOException {
        String query = readConfigFile();


        query = query
                .replace(
                        ES_QUERY_PARAM_USERNAME, params.get("username")
                ).replace(
                        ES_QUERY_PARAM_DURATION,
                        params.getOrDefault("duration", ES_QUERY_PARAM_DURATION_DEFAULT)
                ).replace(
                        ES_QUERY_PARAM_LOGIC,
                        params.getOrDefault("riskLogic", ES_QUERY_PARAM_LOGIC_DEFAULT)
                ).replace(
                        ES_QUERY_PARAM_THRESHOLD,
                        params.getOrDefault("threshold", ES_QUERY_PARAM_THRESHOLD_DEFAULT)
                );

        return query;
    }

}
