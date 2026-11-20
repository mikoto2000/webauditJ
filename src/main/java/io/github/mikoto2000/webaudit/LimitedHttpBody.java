package io.github.mikoto2000.webaudit;
import java.io.*;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.*;
final class LimitedHttpBody implements HttpResponse.BodySubscriber<Void>{
        private final OutputStream out;private final long limit;private long count;private Flow.Subscription subscription;private final CompletableFuture<Void> done=new CompletableFuture<>();
        LimitedHttpBody(OutputStream out,long limit){this.out=out;this.limit=limit;}
        public CompletionStage<Void> getBody(){return done;}
        public void onSubscribe(Flow.Subscription subscription){this.subscription=subscription;subscription.request(1);}
        public void onNext(List<ByteBuffer> chunks){try{for(var chunk:chunks){int n=chunk.remaining();count+=n;if(count>limit)throw new IOException("GeoIP transfer exceeds size limit");byte[] bytes=new byte[n];chunk.get(bytes);out.write(bytes);}subscription.request(1);}catch(Exception ex){subscription.cancel();done.completeExceptionally(ex);}}
        public void onError(Throwable error){done.completeExceptionally(error);}public void onComplete(){done.complete(null);}
    }
