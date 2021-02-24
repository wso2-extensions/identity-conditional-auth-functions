package org.wso2.carbon.identity.conditional.auth.functions.user.grpc;

import static io.grpc.MethodDescriptor.generateFullMethodName;
import static io.grpc.stub.ClientCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ClientCalls.asyncClientStreamingCall;
import static io.grpc.stub.ClientCalls.asyncServerStreamingCall;
import static io.grpc.stub.ClientCalls.asyncUnaryCall;
import static io.grpc.stub.ClientCalls.blockingServerStreamingCall;
import static io.grpc.stub.ClientCalls.blockingUnaryCall;
import static io.grpc.stub.ClientCalls.futureUnaryCall;
import static io.grpc.stub.ServerCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ServerCalls.asyncClientStreamingCall;
import static io.grpc.stub.ServerCalls.asyncServerStreamingCall;
import static io.grpc.stub.ServerCalls.asyncUnaryCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedStreamingCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.15.0)",
    comments = "Source: Service.proto")
public final class grpcServiceGrpc {

  private grpcServiceGrpc() {}

  public static final String SERVICE_NAME = "grpcService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request,
      org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response> getGrpcInvokeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "grpcInvoke",
      requestType = org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request.class,
      responseType = org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request,
      org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response> getGrpcInvokeMethod() {
    io.grpc.MethodDescriptor<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request, org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response> getGrpcInvokeMethod;
    if ((getGrpcInvokeMethod = grpcServiceGrpc.getGrpcInvokeMethod) == null) {
      synchronized (grpcServiceGrpc.class) {
        if ((getGrpcInvokeMethod = grpcServiceGrpc.getGrpcInvokeMethod) == null) {
          grpcServiceGrpc.getGrpcInvokeMethod = getGrpcInvokeMethod = 
              io.grpc.MethodDescriptor.<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request, org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(
                  "grpcService", "grpcInvoke"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response.getDefaultInstance()))
                  .setSchemaDescriptor(new grpcServiceMethodDescriptorSupplier("grpcInvoke"))
                  .build();
          }
        }
     }
     return getGrpcInvokeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest,
      org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse> getSendJsonMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "sendJson",
      requestType = org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest.class,
      responseType = org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest,
      org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse> getSendJsonMethod() {
    io.grpc.MethodDescriptor<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest, org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse> getSendJsonMethod;
    if ((getSendJsonMethod = grpcServiceGrpc.getSendJsonMethod) == null) {
      synchronized (grpcServiceGrpc.class) {
        if ((getSendJsonMethod = grpcServiceGrpc.getSendJsonMethod) == null) {
          grpcServiceGrpc.getSendJsonMethod = getSendJsonMethod = 
              io.grpc.MethodDescriptor.<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest, org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(
                  "grpcService", "sendJson"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse.getDefaultInstance()))
                  .setSchemaDescriptor(new grpcServiceMethodDescriptorSupplier("sendJson"))
                  .build();
          }
        }
     }
     return getSendJsonMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static grpcServiceStub newStub(io.grpc.Channel channel) {
    return new grpcServiceStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static grpcServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new grpcServiceBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static grpcServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new grpcServiceFutureStub(channel);
  }

  /**
   */
  public static abstract class grpcServiceImplBase implements io.grpc.BindableService {

    /**
     */
    public void grpcInvoke(org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request request,
        io.grpc.stub.StreamObserver<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response> responseObserver) {
      asyncUnimplementedUnaryCall(getGrpcInvokeMethod(), responseObserver);
    }

    /**
     */
    public void sendJson(org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest request,
        io.grpc.stub.StreamObserver<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse> responseObserver) {
      asyncUnimplementedUnaryCall(getSendJsonMethod(), responseObserver);
    }

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            getGrpcInvokeMethod(),
            asyncUnaryCall(
              new MethodHandlers<
                org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request,
                org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response>(
                  this, METHODID_GRPC_INVOKE)))
          .addMethod(
            getSendJsonMethod(),
            asyncUnaryCall(
              new MethodHandlers<
                org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest,
                org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse>(
                  this, METHODID_SEND_JSON)))
          .build();
    }
  }

  /**
   */
  public static final class grpcServiceStub extends io.grpc.stub.AbstractStub<grpcServiceStub> {
    private grpcServiceStub(io.grpc.Channel channel) {
      super(channel);
    }

    private grpcServiceStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected grpcServiceStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new grpcServiceStub(channel, callOptions);
    }

    /**
     */
    public void grpcInvoke(org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request request,
        io.grpc.stub.StreamObserver<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(getGrpcInvokeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void sendJson(org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest request,
        io.grpc.stub.StreamObserver<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(getSendJsonMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   */
  public static final class grpcServiceBlockingStub extends io.grpc.stub.AbstractStub<grpcServiceBlockingStub> {
    private grpcServiceBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private grpcServiceBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected grpcServiceBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new grpcServiceBlockingStub(channel, callOptions);
    }

    /**
     */
    public org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response grpcInvoke(org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request request) {
      return blockingUnaryCall(
          getChannel(), getGrpcInvokeMethod(), getCallOptions(), request);
    }

    /**
     */
    public org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse sendJson(org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest request) {
      return blockingUnaryCall(
          getChannel(), getSendJsonMethod(), getCallOptions(), request);
    }
  }

  /**
   */
  public static final class grpcServiceFutureStub extends io.grpc.stub.AbstractStub<grpcServiceFutureStub> {
    private grpcServiceFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private grpcServiceFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected grpcServiceFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new grpcServiceFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response> grpcInvoke(
        org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request request) {
      return futureUnaryCall(
          getChannel().newCall(getGrpcInvokeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse> sendJson(
        org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest request) {
      return futureUnaryCall(
          getChannel().newCall(getSendJsonMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_GRPC_INVOKE = 0;
  private static final int METHODID_SEND_JSON = 1;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final grpcServiceImplBase serviceImpl;
    private final int methodId;

    MethodHandlers(grpcServiceImplBase serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_GRPC_INVOKE:
          serviceImpl.grpcInvoke((org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Request) request,
              (io.grpc.stub.StreamObserver<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.Response>) responseObserver);
          break;
        case METHODID_SEND_JSON:
          serviceImpl.sendJson((org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonRequest) request,
              (io.grpc.stub.StreamObserver<org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.JsonResponse>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  private static abstract class grpcServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    grpcServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return org.wso2.carbon.identity.conditional.auth.functions.user.grpc.Service.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("grpcService");
    }
  }

  private static final class grpcServiceFileDescriptorSupplier
      extends grpcServiceBaseDescriptorSupplier {
    grpcServiceFileDescriptorSupplier() {}
  }

  private static final class grpcServiceMethodDescriptorSupplier
      extends grpcServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final String methodName;

    grpcServiceMethodDescriptorSupplier(String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (grpcServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new grpcServiceFileDescriptorSupplier())
              .addMethod(getGrpcInvokeMethod())
              .addMethod(getSendJsonMethod())
              .build();
        }
      }
    }
    return result;
  }
}
