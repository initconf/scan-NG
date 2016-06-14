# scan-NG


Please make sure you have this temp fix - Real fixed here:  https://bro-tracker.atlassian.net/browse/BIT-1612


--- src/probabilistic/CardinalityCounter.cc.orig        2016-06-08 00:58:49.358750329 -0700
+++ src/probabilistic/CardinalityCounter.cc     2016-06-08 00:58:22.862749444 -0700
@@ -91,6 +91,9 @@
        {
        uint8_t answer = 0;

+       if(hash_modified == 0 )
+               return answer ;
+
        hash_modified = (uint64)(hash_modified / m);
        hash_modified *= 2;
