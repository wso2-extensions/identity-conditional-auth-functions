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
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service;
import org.wso2.carbon.identity.conditional.auth.functions.user.grpc.grpcServiceGrpc;

import java.util.Map;

/**
 * Function to send Json object to a remote gRPC server.
 */
public class GrpcInvokeFunctionImpl implements GrpcInvokeFunction {

    private static final Log log = LogFactory.getLog(GrpcInvokeFunctionImpl.class);

    @Override
    public String grpcInvoke(String host, String port, Object params) {

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

            // Create the gRPC client stub.
            grpcServiceGrpc.grpcServiceBlockingStub clientStub = grpcServiceGrpc.newBlockingStub(channel);

            // Define the request message.
            Service.JsonRequest jsonRequest = Service.JsonRequest.newBuilder().setJsonString(jsonString).build();

            // Obtain response message from gRPC server.
            String jsonResponse = clientStub.grpcInvoke(jsonRequest).getJsonString();

            String jsResponse = "gRPC server returns Json String: " + jsonResponse;

            return jsResponse;

        } else {

            log.error("Cannot find a map object in method parameters");
            return "Cannot find a map object. Incorrect definition of method parameters.";

        }
    }
}
