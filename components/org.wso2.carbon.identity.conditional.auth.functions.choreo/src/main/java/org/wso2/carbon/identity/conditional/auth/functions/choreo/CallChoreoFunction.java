
package org.wso2.carbon.identity.conditional.auth.functions.choreo;

import java.util.Map;

/**
 * Function to publish events to analytics engine and get the output event synchronously.
 */
@FunctionalInterface
public interface CallChoreoFunction {

    /**
     *  Publish data to analytics engine and get the decision.
     *
     * @param serviceName Metadata to call the endpoint.
     * @param payloadData payload data.
     * @param eventHandlers event handlers.
     */
    void callChoreo(String serviceName, Map<String, Object> payloadData,
                    Map<String, Object> eventHandlers);
}