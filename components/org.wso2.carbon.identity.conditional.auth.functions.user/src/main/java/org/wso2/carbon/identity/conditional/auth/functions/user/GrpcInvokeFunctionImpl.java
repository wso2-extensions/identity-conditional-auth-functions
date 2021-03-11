/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.user;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
<<<<<<< HEAD
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
=======
>>>>>>> 4a946ea0bcd4b3fbbbeff7ab7e4d7e53dd744ecf
import org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service;
import org.wso2.carbon.identity.conditional.auth.functions.user.grpc.grpcServiceGrpc;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;
<<<<<<< HEAD

import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_SUCCESS;
=======
>>>>>>> 4a946ea0bcd4b3fbbbeff7ab7e4d7e53dd744ecf

/**
 * Function to send Json object to a remote gRPC server.
 */
public class GrpcInvokeFunctionImpl implements GrpcInvokeFunction {

    private static final Log log = LogFactory.getLog(GrpcInvokeFunctionImpl.class);
    String jsonResponse = null;

    @Override
    public String grpcInvoke(String host, String port, Object params, Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((context, asyncReturn) -> {

            JSONObject jsonObject = new JSONObject();
            Map<String, Object> properties = null;

            if (params instanceof Map) {

                properties = (Map<String, Object>) params;
                for (Map.Entry<String, Object> entry : properties.entrySet()) {

                    jsonObject.put(entry.getKey(), entry.getValue());
                }
                // Converts the Json object into a Json string.
                String jsonString = jsonObject.toJSONString();

                // Create the channel for gRPC server.
                ManagedChannel channel = NettyChannelBuilder.forAddress(host, Integer.parseInt(port)).usePlaintext()
                        .build();

<<<<<<< HEAD
                // Create the gRPC client stub.
                grpcServiceGrpc.grpcServiceBlockingStub clientStub = grpcServiceGrpc.newBlockingStub(channel);
=======
        JSONObject jsonObject = new JSONObject();
        Map<String, Object> properties = null;
>>>>>>> 4a946ea0bcd4b3fbbbeff7ab7e4d7e53dd744ecf

                // Define the request message.
                Service.JsonRequest jsonRequest = Service.JsonRequest.newBuilder().setJsonString(jsonString).build();

<<<<<<< HEAD
                // Obtain response message from gRPC server and sets a deadline.
                try {
                    jsonResponse = clientStub.withDeadlineAfter(5000, TimeUnit.MILLISECONDS)
                            .grpcInvoke(jsonRequest).getJsonString();
                    channel.shutdown();
                    log.debug(jsonResponse);
=======
            properties = (Map<String, Object>) params;
            for (Map.Entry<String, Object> entry : properties.entrySet()) {

                jsonObject.put(entry.getKey(), entry.getValue());
            }
            // Converts the Json object into a Json string.
            String jsonString = jsonObject.toJSONString();
>>>>>>> 4a946ea0bcd4b3fbbbeff7ab7e4d7e53dd744ecf

                    //  Validate the gRPC server response object type.
                    try {
                        JSONParser jsonParser = new JSONParser();
                        JSONObject jsonObject1 = (JSONObject) jsonParser.parse(jsonResponse);
                        asyncReturn.accept(context, jsonObject1, OUTCOME_SUCCESS);

                    } catch (ParseException e) {
                        log.error("gRPC server returns non Json string.", e);
                        jsonResponse = null;
                        asyncReturn.accept(context, Collections.emptyMap(), OUTCOME_FAIL);

<<<<<<< HEAD
                    }

                    // Handle the exceptions.
                } catch (StatusRuntimeException e) {
                    if (e.getStatus().getCode() == Status.Code.DEADLINE_EXCEEDED) {
                        log.error("gRPC connection deadline exceeded.", e);
                        jsonResponse = null;
                        asyncReturn.accept(context, Collections.emptyMap(), OUTCOME_FAIL);

                    } else if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                        log.error("gRPC service is unavailable at " + host + ":" + port, e);
                        jsonResponse = null;
                        asyncReturn.accept(context, Collections.emptyMap(), OUTCOME_FAIL);

                    } else if (e.getStatus().getCode() == Status.Code.UNIMPLEMENTED) {
                        log.error("Operation not implemented in the service at " + host + ":" + port, e);
                        jsonResponse = null;
                        asyncReturn.accept(context, Collections.emptyMap(), OUTCOME_FAIL);
=======
            // Define the request message.
            Service.JsonRequest jsonRequest = Service.JsonRequest.newBuilder().setJsonString(jsonString).build();

            // Obtain response message from gRPC server and sets a deadline.
            try {
                String jsonResponse = clientStub.withDeadlineAfter(5000, TimeUnit.MILLISECONDS)
                        .grpcInvoke(jsonRequest).getJsonString();

                //  Validate the gRPC server response object type.
                try {
                    JSONParser jsonParser = new JSONParser();
                    JSONObject jsonObject1 = (JSONObject) jsonParser.parse(jsonResponse);
                    return jsonResponse;
                } catch (ParseException e) {
                    log.error("gRPC server returns non Json string.", e);
                    return null;
                }

                // Handle the exceptions.
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.DEADLINE_EXCEEDED) {
                    log.error("gRPC connection deadline exceeded.", e);
                    return null;
                }
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("gRPC service is unavailable at " + host + ":" + port, e);
                    return null;
                }
                if (e.getStatus().getCode() == Status.Code.UNIMPLEMENTED) {
                    log.error("Operation not implemented in the service at " + host + ":" + port, e);
                    return null;
                }
                if (e.getStatus().getCode() == Status.Code.UNKNOWN) {
                    log.error("gRPC server threw unknown exception at " + host + ":" + port, e);
                    return null;
                }
                log.error("gRPC service failure. " + e.getStatus().toString());
                return null;
            }
>>>>>>> 4a946ea0bcd4b3fbbbeff7ab7e4d7e53dd744ecf

                    } else if (e.getStatus().getCode() == Status.Code.UNKNOWN) {
                        log.error("gRPC server threw unknown exception at " + host + ":" + port, e);
                        jsonResponse = null;
                        asyncReturn.accept(context, Collections.emptyMap(), OUTCOME_FAIL);

<<<<<<< HEAD
                    } else {
                        log.error("gRPC service failure. " + e.getStatus().toString());
                        jsonResponse = null;
                        asyncReturn.accept(context, Collections.emptyMap(), OUTCOME_FAIL);
                    }

                } catch (FrameworkException e) {
                    log.error("Error while proceeding after successful response from gRPC server", e);
                }

            } else {

                log.error("Incorrect definition of method parameters. Cannot find a Json Object.");
                jsonResponse = null;
                asyncReturn.accept(context, Collections.emptyMap(), OUTCOME_FAIL);

            }
        });

        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);

        return jsonResponse;

=======
            log.error("Cannot find a Json object in method parameters. Incorrect definition of method parameters.");
            return null;

        }
>>>>>>> 4a946ea0bcd4b3fbbbeff7ab7e4d7e53dd744ecf
    }

}
