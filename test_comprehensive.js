// Comprehensive test: Java bridge + anti-detection + hooks
setTimeout(function() {
    // === ANTI-DETECTION CHECKS ===

    // 1. /proc/self/maps
    var maps_clean = true;
    try {
        var f = new File('/proc/self/maps', 'r');
        var maps = f.readAllText();
        f.close();
        var lines = maps.split('\n');
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].toLowerCase().indexOf('frida') >= 0) {
                maps_clean = false;
                console.log('[DETECT] maps: ' + lines[i].trim());
            }
        }
    } catch(e) {}
    console.log('[ANTIDETECT] maps: ' + (maps_clean ? 'CLEAN' : 'DETECTED'));

    // 2. Thread names
    var threads = Process.enumerateThreads();
    var suspicious_threads = [];
    for (var i = 0; i < threads.length; i++) {
        try {
            var f2 = new File('/proc/self/task/' + threads[i].id + '/comm', 'r');
            var name = f2.readAllText().trim();
            f2.close();
            var lower = name.toLowerCase();
            if (lower.indexOf('frida') >= 0 || name === 'gmain' || name === 'gdbus' ||
                name === 'gum-js-loop' || name === 'pool-spawner') {
                suspicious_threads.push(name);
            }
        } catch(e) {}
    }
    console.log('[ANTIDETECT] threads: ' + (suspicious_threads.length === 0 ? 'CLEAN' : 'DETECTED: ' + suspicious_threads.join(', ')));

    // 3. Modules
    var mods = Process.enumerateModules();
    var frida_mods = [];
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.toLowerCase().indexOf('frida') >= 0) {
            frida_mods.push(mods[i].name);
        }
    }
    console.log('[ANTIDETECT] modules: ' + (frida_mods.length === 0 ? 'CLEAN (' + mods.length + ' total)' : 'DETECTED: ' + frida_mods.join(', ')));

    // 4. frida_agent_main export
    try {
        var agent_main = Module.findExportByName(null, 'frida_agent_main');
        console.log('[ANTIDETECT] frida_agent_main: ' + (agent_main === null ? 'CLEAN' : 'DETECTED @ ' + agent_main));
    } catch(e) {
        console.log('[ANTIDETECT] frida_agent_main: CLEAN (export lookup failed)');
    }

    // === JAVA BRIDGE TESTS ===
    if (typeof Java !== 'undefined' && Java.available) {
        Java.perform(function() {
            console.log('[JAVA] available: true');
            console.log('[JAVA] android: ' + Java.androidVersion);

            var classes = Java.enumerateLoadedClassesSync();
            console.log('[JAVA] classes: ' + classes.length);

            // Java.use tests
            var tests = [
                'java.lang.String',
                'android.app.Activity',
                'javax.crypto.Cipher',
                'android.content.SharedPreferences',
                'java.net.URL'
            ];
            for (var i = 0; i < tests.length; i++) {
                try {
                    Java.use(tests[i]);
                    console.log('[JAVA] use(' + tests[i] + '): OK');
                } catch(e) {
                    console.log('[JAVA] use(' + tests[i] + '): FAIL - ' + e);
                }
            }

            // Hook test
            try {
                var Activity = Java.use('android.app.Activity');
                Activity.onCreate.overload('android.os.Bundle').implementation = function(b) {
                    console.log('[HOOK] Activity.onCreate: ' + this.getClass().getName());
                    this.onCreate(b);
                };
                console.log('[JAVA] hook Activity.onCreate: OK');
            } catch(e) {
                console.log('[JAVA] hook Activity.onCreate: FAIL - ' + e);
            }

            // Thread check from Java side
            try {
                var Thread = Java.use('java.lang.Thread');
                var threadSet = Thread.getAllStackTraces();
                var iter = threadSet.keySet().iterator();
                var java_suspicious = [];
                while (iter.hasNext()) {
                    var t = iter.next();
                    var name = t.getName();
                    var lower = name.toLowerCase();
                    if (lower.indexOf('frida') >= 0 || name === 'gmain' || name === 'gdbus' ||
                        name === 'gum-js-loop' || name === 'pool-spawner') {
                        java_suspicious.push(name);
                    }
                }
                console.log('[ANTIDETECT] java threads: ' + (java_suspicious.length === 0 ? 'CLEAN' : 'DETECTED: ' + java_suspicious.join(', ')));
            } catch(e) {
                console.log('[ANTIDETECT] java threads: ERROR - ' + e);
            }

            // Maps check from Java
            try {
                var Runtime = Java.use('java.lang.Runtime');
                var proc = Runtime.getRuntime().exec('cat /proc/self/maps');
                var is = proc.getInputStream();
                var buf = Java.array('byte', new Array(65536).fill(0));
                var total = '';
                var n;
                while ((n = is.read(buf)) > 0) {
                    for (var j = 0; j < n; j++) {
                        total += String.fromCharCode(buf[j] & 0xFF);
                    }
                }
                is.close();
                var java_maps_clean = total.toLowerCase().indexOf('frida') === -1;
                console.log('[ANTIDETECT] java maps: ' + (java_maps_clean ? 'CLEAN' : 'DETECTED'));
            } catch(e) {
                console.log('[ANTIDETECT] java maps: ERROR');
            }

            console.log('[TEST] ALL DONE');
        });
    } else {
        console.log('[JAVA] NOT AVAILABLE');
        console.log('[TEST] ALL DONE');
    }
}, 2000);
