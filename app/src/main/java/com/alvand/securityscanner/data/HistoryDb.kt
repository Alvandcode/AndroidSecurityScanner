package com.alvand.securityscanner.data

import android.content.Context
import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "scans")
data class ScanRecord(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val deviceScore: Int,
    val appsScanned: Int,
    val threats: Int,
    // Compact summary: "pkg:score;pkg:score..." (top threats only, max ~2KB)
    val summary: String,
    // Phase-3 file scan (default 0 keeps v1 rows readable after destructive fallback)
    val filesScanned: Int = 0,
    val fileThreats: Int = 0,
    val fileSummary: String = ""
)

@Dao
interface ScanDao {
    @Query("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50")
    fun recent(): Flow<List<ScanRecord>>

    @Insert
    suspend fun insert(r: ScanRecord)

    @Query("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY timestamp DESC LIMIT 50)")
    suspend fun trim()
}

@Database(entities = [ScanRecord::class], version = 2, exportSchema = false)
abstract class HistoryDb : RoomDatabase() {
    abstract fun dao(): ScanDao

    companion object {
        @Volatile private var inst: HistoryDb? = null
        fun get(ctx: Context): HistoryDb = inst ?: synchronized(this) {
            inst ?: Room.databaseBuilder(ctx.applicationContext, HistoryDb::class.java, "history.db")
                // v1->v2 only adds file columns; history is disposable (max 50 rows).
                .fallbackToDestructiveMigration()
                .build().also { inst = it }
        }
    }
}
