# TrustCheck R8 rules

# kotlinx.serialization: keep generated serializers for backend DTOs.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class com.mesflit.trustcheck.core.network.dto.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.mesflit.trustcheck.core.network.dto.**$$serializer { *; }

-keepclassmembers class com.mesflit.trustcheck.core.network.ThreatFeed* {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.mesflit.trustcheck.core.network.ThreatFeed*$$serializer { *; }

# WorkManager workers are instantiated reflectively by class name.
-keep class * extends androidx.work.ListenableWorker { <init>(...); }

# OkHttp platform warnings
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
