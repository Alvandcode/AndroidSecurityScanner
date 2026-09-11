# keep scanner classes
-keep class com.alvand.securityscanner.scanner.** { *; }
# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-dontwarn androidx.room.**
# WorkManager
-keep class * extends androidx.work.Worker
-keep class * extends androidx.work.CoroutineWorker
# DataStore / protobuf
-keep class androidx.datastore.** { *; }
