package com.alvand.securityscanner.data

import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey

object PrefsKeys {
    val THEME = stringPreferencesKey("theme") // system|light|dark
    val LANG = stringPreferencesKey("lang") // system|en|fa
    val LAST_SCORE = stringPreferencesKey("last_score")
    val LAST_SCAN = stringPreferencesKey("last_scan")
    // Phase-2
    val CLOUD = booleanPreferencesKey("cloud_lookup") // opt-in, default false
    val VT_KEY = stringPreferencesKey("vt_api_key")
    val SCHED = booleanPreferencesKey("scheduled_scan") // default false
    // Phase-3: user-granted SAF folder for file scan (persisted tree uri string)
    val FILE_TREE = stringPreferencesKey("file_tree_uri")
}
