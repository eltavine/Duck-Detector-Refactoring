# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

-obfuscationdictionary dir.txt
-classobfuscationdictionary dir.txt
-packageobfuscationdictionary dir.txt
-repackageclasses ''

-keep class com.tencent.soter.** { *; }
-dontwarn com.tencent.soter.**

# Native preload launches MainActivity by explicit component name before Compose starts.
-keepnames class com.eltavine.duckdetector.MainActivity

# DashboardExportFormatter reflects over shared UI row models when building
# exported reports. Keep the field names stable in release builds so R8 does
# not strip detector card details from the text export.
-keepclassmembers class com.eltavine.duckdetector.features.**.ui.model.** {
    java.lang.String label;
    java.lang.String value;
    java.lang.String detail;
    java.lang.String text;
}
