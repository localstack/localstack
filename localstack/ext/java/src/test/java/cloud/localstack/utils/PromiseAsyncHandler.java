package cloud.localstack.utils;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.handlers.AsyncHandler;

import java.util.concurrent.CompletableFuture;

public class PromiseAsyncHandler<T extends AmazonWebServiceRequest, R> extends CompletableFuture<R> implements AsyncHandler<T, R> {
    @Override
    public void onError(Exception exception) {
        completeExceptionally(exception);
    }

    @Override
    public void onSuccess(T request, R r) {
      complete(r);
    }
}
