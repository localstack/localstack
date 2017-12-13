package cloud.localstack.docker.command;

import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class RegexStream {

    private final MatcherSpliterator matcherSpliterator;

    public RegexStream(Matcher matcher) {
        this.matcherSpliterator = new MatcherSpliterator(matcher);
    }

    public Stream<Matcher> stream(){
        return StreamSupport.stream(matcherSpliterator, false);
    }


    private class MatcherSpliterator implements Spliterator<Matcher> {

        private final Matcher matcher;
        public MatcherSpliterator(Matcher matcher) {
            this.matcher = matcher;
        }

        @Override
        public boolean tryAdvance(Consumer<? super Matcher> action) {
            boolean found = matcher.find();
            if(found) {
                action.accept(matcher);
            }
            return found;
        }

        @Override
        public Spliterator<Matcher> trySplit() {
            return null;
        }

        @Override
        public long estimateSize() {
            return 0;
        }

        @Override
        public int characteristics() {
            return 0;
        }
    }
}
