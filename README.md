# LAB 11 — Bypass de la Détection de Root Android avec Frida (Hooks Java & Natif)

**Cours : Sécurité des applications mobiles**
**Niveau : Intermédiaire**

---


## Objectifs du laboratoire

À l'issue de cette séance, l'étudiant sera capable de :

- Expliquer les principaux mécanismes par lesquels une application Android détecte la présence d'un environnement rooté, aussi bien au niveau Java qu'au niveau natif.
- Écrire et déployer un script Frida capable de neutraliser ces détections par hooking de méthodes Java.
- Étendre le bypass au niveau natif lorsque la détection est implémentée en C/C++ dans une librairie `.so`.
- Identifier et contourner les mécanismes anti-Frida élémentaires présents dans certaines applications.
- Diagnostiquer les échecs courants lors du déploiement d'un script de bypass.

---

## Prérequis

- Frida 17.x installé sur la machine hôte (`frida --version` doit retourner une version cohérente avec le serveur embarqué).
- `frida-tools` installés via pip (`frida-ps`, `frida-trace` disponibles en ligne de commande).
- Android Emulator fonctionnel (API 28 ou inférieur recommandé), reconnu par ADB (`adb devices` retourne `emulator-5554 device`).
- `frida-server` correspondant exactement à la version du client hôte, transféré dans `/data/local/tmp/` sur l'émulateur.
- Application cible installée sur l'émulateur et identifiée par son package name.
- Connaissances de base en Java Android et en lecture de code décompilé (Jadx).

---

## Rappel — Démarrer frida-server sur l'émulateur Android

Avant tout hook, le serveur Frida doit être actif sur l'émulateur. Les captures d'écran jointes montrent l'intégralité de cette séquence.

**Transfert et configuration des permissions :**

```powershell
.\adb.exe push frida-server /data/local/tmp/
.\adb.exe shell chmod 755 /data/local/tmp/frida-server
```

**Élévation de privilèges et démarrage :**

```powershell
.\adb.exe root
.\adb.exe shell "/data/local/tmp/frida-server &"
```

La commande `adb root` relance le démon ADB avec les droits root, ce qui est indispensable pour que frida-server puisse s'instrumenter dans les processus système. Si le serveur est déjà en cours d'exécution, la tentative de reliancement retourne `Address already in use` — ce comportement, visible sur la capture, est normal et signifie que le serveur est déjà opérationnel.

**Vérification de la connexion :**

```powershell
frida-ps -Uai
```

Cette commande liste tous les processus visibles par Frida sur le device USB (ou émulateur). La sortie attendue est un tableau avec les colonnes PID, Name et Identifier. Les applications en cours d'exécution affichent un PID ; celles qui sont installées mais inactives affichent un tiret. Comme visible sur les captures, les applications PwnSec (`com.PwnSec.fireinthehole`, `com.pwnsec.firestorm`) apparaissent dans la liste aux côtés des applications système Android.

**Vérification de la cohérence des versions :**

```powershell
frida --version
python -c "import frida; print(frida.__version__)"
```

Les deux commandes doivent retourner la même version — `17.9.1` dans l'environnement de lab illustré. Une divergence entre la version client et la version du serveur embarqué est la première cause d'échec de connexion.

---

## Panorama des techniques de détection de root

Comprendre ce que l'on cherche à contourner est indispensable avant d'écrire le moindre hook. Les détections de root se répartissent en deux grandes familles selon la couche où elles opèrent.

### Détections au niveau Java / Kotlin

Ces vérifications sont implémentées dans le code applicatif et sont les plus simples à identifier via Jadx et à neutraliser via Frida.

**Vérification de `Build.TAGS`** : le champ `android.os.Build.TAGS` contient la chaîne `test-keys` sur les builds rootés avec des clés non officielles, contre `release-keys` sur un appareil non modifié. De nombreuses applications comparent ce champ directement.

**Détection de binaires suspects** : vérification de l'existence de fichiers comme `/system/app/Superuser.apk`, `/system/xbin/su`, `/sbin/su`, ou `/system/bin/su` via `File.exists()` ou des appels à `Runtime.exec("which su")`.

**Tentative d'exécution de `su`** : l'application tente d'exécuter `su` et infère la présence de root selon que la commande réussit ou échoue.

**Inspection des packages installés** : recherche des packages associés aux frameworks de root (`com.topjohnwu.magisk`, `eu.chainfire.supersu`, etc.) via le `PackageManager`.

**Vérification des propriétés système** : lecture de propriétés comme `ro.debuggable`, `ro.secure` ou `ro.build.tags` via `SystemProperties` ou `getprop`.

### Détections au niveau natif (C/C++)

Ces détections opèrent dans des librairies `.so` et sont plus résistantes à l'analyse statique. Elles requièrent un hooking au niveau natif.

**Appels système directs** : utilisation directe de `open()`, `access()`, `stat()` pour vérifier l'existence de fichiers caractéristiques d'un environnement rooté, en contournant les abstractions Java.

**Inspection du système de fichiers** : lecture de `/proc/self/maps` pour détecter des montages suspects ou des librairies injectées.

**Détection de Frida lui-même** : recherche du port 27042 (`frida-server` par défaut), scan de `/proc/self/maps` pour les librairies `frida-agent`, ou détection du thread nommé `gmain` caractéristique de Frida.

---

## Étape 1 — Identification du package et du processus cible

Avant d'écrire un script, il faut identifier avec précision le package name de l'application cible et observer son comportement au démarrage.

**Lister les applications disponibles :**

```powershell
frida-ps -Uai
```

Repérer le package name de l'application cible dans la colonne Identifier. Pour les labs PwnSec, les identifiants observés sont `com.PwnSec.fireinthehole` et `com.pwnsec.firestorm`.

**Lancer l'application cible sur l'émulateur** et noter si elle se ferme immédiatement — comportement caractéristique d'une détection de root active au démarrage.

**Identifier les méthodes de détection via Jadx** : décompiler l'APK et rechercher les patterns décrits dans la section précédente. Relever les noms de classes et de méthodes exacts, car Frida est sensible à la casse.

---

## Étape 2 — Script Frida : bypass Java

Ce script couvre les détections Java les plus courantes. Il est conçu pour être chargé au démarrage du processus (`-l` flag) afin d'intercepter les vérifications avant qu'elles ne soient exécutées.

Créer le fichier `bypass_root.js` :

```javascript
Java.perform(function () {

    // --- 1. Hook Build.TAGS ---
    // Retourne "release-keys" quelle que soit la valeur réelle
    var Build = Java.use("android.os.Build");
    Object.defineProperty(Build, "TAGS", {
        get: function () { return "release-keys"; }
    });
    console.log("[+] Hook Build.TAGS -> release-keys");

    // --- 2. Hook File.exists() ---
    // Neutralise les vérifications de présence de binaires et fichiers suspects
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        var suspiciousPaths = [
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/sbin/su",
            "/system/bin/su",
            "/system/bin/.ext/.su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        ];
        for (var i = 0; i < suspiciousPaths.length; i++) {
            if (path === suspiciousPaths[i]) {
                console.log("[+] File.exists() intercepté pour : " + path + " -> false");
                return false;
            }
        }
        return this.exists();
    };

    // --- 3. Hook Runtime.exec() ---
    // Bloque les tentatives d'exécution de "su" ou de "which su"
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[+] Runtime.exec() bloqué : " + cmd);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
        for (var i = 0; i < cmds.length; i++) {
            if (cmds[i].indexOf("su") !== -1) {
                console.log("[+] Runtime.exec([]) bloqué");
                throw Java.use("java.io.IOException").$new("Command not found");
            }
        }
        return this.exec(cmds);
    };

    // --- 4. Hook PackageManager.getPackageInfo() ---
    // Empêche la détection de packages Magisk / SuperSU
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload(
        "java.lang.String", "int"
    ).implementation = function (packageName, flags) {
        var rootPackages = [
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine"
        ];
        for (var i = 0; i < rootPackages.length; i++) {
            if (packageName === rootPackages[i]) {
                console.log("[+] getPackageInfo() bloqué pour : " + packageName);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(packageName);
            }
        }
        return this.getPackageInfo(packageName, flags);
    };

    // --- 5. Hook des propriétés système ---
    // Force ro.debuggable et ro.secure à des valeurs sûres
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            if (key === "ro.build.tags") return "release-keys";
            return this.get(key);
        };
        console.log("[+] Hook SystemProperties installé");
    } catch (e) {
        console.log("[*] SystemProperties non accessible : " + e.message);
    }

    // --- 6. Hook classes de détection spécifiques à l'app ---
    // À adapter selon le résultat de l'analyse Jadx
    // Exemple générique : forcer une méthode isRooted() à retourner false
    /*
    try {
        var RootDetector = Java.use("com.example.app.security.RootDetector");
        RootDetector.isRooted.implementation = function () {
            console.log("[+] isRooted() -> false");
            return false;
        };
    } catch (e) {
        console.log("[*] Classe RootDetector non trouvée : " + e.message);
    }
    */

    console.log("[+] Java layer bypass installé");
});
```

**Déploiement :**

```powershell
# Attacher au processus déjà lancé (remplacer 8065 par le PID réel)
frida -U -p 8065 -l bypass_root.js

# Ou spawner l'application directement
frida -U -f com.exemple.app -l bypass_root.js --no-pause
```

Comme visible sur les captures, le script produit une sortie confirmant chaque hook installé : `[+] Hook Build.TAGS -> release-keys`, `[+] Hooks Runtime.exec installés`, `[+] Java layer bypass installé`. La mention `[*] RootBeer non présent` indique que la classe de détection ciblée n'a pas été trouvée dans cette version de l'application — comportement attendu et non bloquant.

---

## Étape 3 — Hooks natifs (détections en C/C++)

Lorsque la détection survit au bypass Java, elle est probablement implémentée dans une librairie native. Les captures `frida-trace` illustrent cette situation : les appels `open()`, `access()` et `stat()` de `libc.so` sont interceptés en temps réel.

### Traçage préliminaire avec frida-trace

Avant d'écrire un hook natif, observer quelles fonctions système sont appelées par l'application :

```powershell
frida-trace -U -p 8065 -i open -i access -i stat
```

Comme visible sur les captures, frida-trace génère automatiquement des handlers dans le dossier `__handlers__/libc.so/` et ouvre une interface web sur `localhost:52665` pour visualiser les événements en temps réel. L'interface affiche le code source du handler `open.js`, les Thread IDs, et les call stacks — notamment le caller `libartbase.so` identifié dans la popup de détail.

Cette trace permet d'identifier si l'application appelle `open("/system/xbin/su")` ou `access("/sbin/su")` directement depuis du code natif.

### Script de bypass natif

Créer le fichier `bypass_native.js` :

```javascript
// Bypass natif : neutralise les vérifications filesystem en C/C++
var libc = Process.getModuleByName("libc.so");

// --- Hook open() ---
var openPtr = libc.getExportByName("open");
Interceptor.attach(openPtr, {
    onEnter: function (args) {
        var path = args[0].readUtf8String();
        var suspiciousPaths = [
            "/system/xbin/su",
            "/sbin/su",
            "/system/bin/su",
            "/system/app/Superuser.apk",
            "/proc/self/maps"   // si utilisé pour détecter Frida
        ];
        for (var i = 0; i < suspiciousPaths.length; i++) {
            if (path && path.indexOf(suspiciousPaths[i]) !== -1) {
                console.log("[+] open() intercepté : " + path + " -> redirection vers /dev/null");
                args[0] = Memory.allocUtf8String("/dev/null");
            }
        }
    }
});

// --- Hook access() ---
var accessPtr = libc.getExportByName("access");
Interceptor.attach(accessPtr, {
    onEnter: function (args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function (retval) {
        var rootPaths = ["/system/xbin/su", "/sbin/su", "/system/bin/su"];
        for (var i = 0; i < rootPaths.length; i++) {
            if (this.path && this.path.indexOf(rootPaths[i]) !== -1) {
                console.log("[+] access() -> -1 pour : " + this.path);
                retval.replace(-1);
            }
        }
    }
});

// --- Hook stat() ---
var statPtr = libc.getExportByName("stat");
Interceptor.attach(statPtr, {
    onEnter: function (args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function (retval) {
        var rootPaths = ["/system/xbin/su", "/sbin/su"];
        for (var i = 0; i < rootPaths.length; i++) {
            if (this.path && this.path.indexOf(rootPaths[i]) !== -1) {
                console.log("[+] stat() -> ENOENT pour : " + this.path);
                retval.replace(-1);
            }
        }
    }
});

console.log("[+] Hooks natifs libc.so installés");
```

**Déploiement :**

```powershell
frida -U -p 8065 -l bypass_native.js
```

Comme visible sur la capture, la connexion s'établit et le prompt `[Android Emulator 5554::PID::8065]->` confirme que Frida est attaché au processus. L'absence de messages d'erreur indique que les hooks ont été installés correctement.

---

## Étape 4 — Contournement des anti-Frida élémentaires (optionnel)

Certaines applications détectent activement la présence de Frida. Les techniques suivantes couvrent les vérifications les plus communes.

**Masquage du port 27042 :**

```javascript
// Intercepte les tentatives de connexion au port Frida par défaut
var Socket = Java.use("java.net.Socket");
Socket.$init.overload("java.lang.String", "int").implementation = function (host, port) {
    if (port === 27042) {
        console.log("[+] Tentative de connexion au port Frida bloquée");
        throw Java.use("java.net.ConnectException").$new("Connection refused");
    }
    return this.$init(host, port);
};
```

**Masquage dans `/proc/self/maps` :**

```javascript
// Intercepte la lecture de /proc/self/maps pour masquer les librairies Frida
var BufferedReader = Java.use("java.io.BufferedReader");
BufferedReader.readLine.implementation = function () {
    var line = this.readLine();
    if (line !== null && (line.indexOf("frida") !== -1 || line.indexOf("gum-js-loop") !== -1)) {
        console.log("[+] Ligne masquée dans /proc/self/maps");
        return this.readLine(); // sauter la ligne compromettante
    }
    return line;
};
```

**Note :** ces techniques fonctionnent contre des détections implémentées en Java. Si la lecture de `/proc/self/maps` se fait depuis du code natif, un hook sur `fgets()` ou `read()` de `libc.so` est nécessaire.

---

## Étape 5 — Méthodes de lancement et cas d'usage

### Spawn vs Attach

**Spawn** (recommandé pour les détections au démarrage) : Frida lance l'application et injecte le script avant l'exécution de la moindre ligne de code applicatif. C'est la seule approche efficace si la détection de root s'exécute dans `Application.onCreate()` ou dans un bloc statique.

```powershell
frida -U -f com.exemple.app -l bypass_root.js --no-pause
```

**Attach** : Frida s'attache à un processus déjà en cours. Utile si la détection n'intervient pas au démarrage mais lors d'une action utilisateur spécifique.

```powershell
frida -U -p <PID> -l bypass_root.js
```

Le PID est obtenu via `frida-ps -Uai` ou `adb shell pidof com.exemple.app`.

### Chargement de plusieurs scripts

```powershell
frida -U -f com.exemple.app -l bypass_root.js -l bypass_native.js --no-pause
```

### Rechargement à chaud pendant le développement

Dans le REPL interactif (`[Android Emulator 5554::PID]→`), la commande `%reload` recharge le script sans relancer l'application — utile pour itérer rapidement sur un bypass en cours de développement.

---

## Validation

Un bypass réussi se manifeste par les indicateurs suivants, à vérifier dans l'ordre :

1. Le terminal affiche les messages `[+]` confirmant l'installation de chaque hook.
2. L'application se lance sans se fermer immédiatement.
3. L'interface de l'application est accessible et fonctionnelle au-delà de l'écran de démarrage.
4. Si un flag ou un message de succès est attendu, il apparaît normalement.
5. `frida-ps -Uai` confirme que l'application est toujours en cours d'exécution (PID présent).

---

## Dépannage

**`frida-server` : Address already in use**
Le serveur est déjà actif — comportement normal. Visible sur la première capture. Ne pas tenter de le relancer ; procéder directement à `frida-ps -Uai` pour vérifier la connexion.

**`frida-ps` retourne une liste vide ou seulement 3 entrées (Clock, Phone, Settings)**
Le serveur est actif mais aucune application n'est ouverte sur l'émulateur. Lancer l'application cible manuellement ou utiliser `frida -U -f` pour la spawner.

**`Failed to attach: unable to find process with name`**
Le package name est incorrect ou l'application n'est pas installée. Vérifier avec `adb shell pm list packages | findstr mot_cle`.

**`websockets.exceptions.InvalidStatus: server rejected WebSocket connection: HTTP 200`**
Erreur visible sur les captures lors de l'utilisation de `frida-trace`. Elle indique une incompatibilité entre la version du client et celle du serveur, ou une interruption de la connexion WebSocket. Vérifier que `frida --version` correspond à la version de `frida-server` embarquée. Reconstruire `frida-server` avec la version exacte si nécessaire.

**L'application se ferme malgré le bypass Java**
La détection passe par du code natif. Ajouter `bypass_native.js` et utiliser `frida-trace` pour identifier les appels système concernés. Vérifier également si la détection utilise la JNI pour appeler des vérifications natives depuis Java.

**`ClassNotFoundException` dans les logs du script**
Le nom de classe utilisé dans `Java.use()` ne correspond pas au nom réel dans l'APK. Vérifier dans Jadx le package et le nom exacts, en tenant compte de l'obfuscation éventuelle (ProGuard).

**`Unable to load SELinux policy from the kernel`**
Avertissement bénin sur certains émulateurs lors du démarrage de `frida-server`. Il n'empêche pas le fonctionnement correct du serveur.

---

## Exercices pratiques (livrables)

**Exercice 1 — Analyse statique préalable**
Décompiler l'APK cible avec Jadx. Identifier et documenter toutes les méthodes de détection de root présentes : nom de classe, nom de méthode, logique de décision. Produire un tableau récapitulatif.

**Exercice 2 — Bypass Java minimal**
Écrire un script ne contenant que les hooks strictement nécessaires pour l'application cible, sans copier-coller le script générique fourni. Justifier chaque hook par une référence au code source décompilé.

**Exercice 3 — Observation native avec frida-trace**
Lancer `frida-trace` sur les fonctions `open`, `access`, `stat` pendant que l'application démarre. Capturer et analyser la sortie. Identifier si des chemins liés au root sont accédés depuis du code natif.

**Exercice 4 — Bypass complet et rapport**
Produire un bypass fonctionnel (Java + natif si nécessaire). Rédiger un rapport d'une page documentant : la liste des détections identifiées, les hooks appliqués, les preuves de succès (captures d'écran logcat / sortie Frida), et les limites de l'approche.

---

## Bonnes pratiques

Toujours commencer par l'analyse statique avant d'écrire des hooks. Un script ciblé sur les méthodes réellement présentes dans l'application est plus fiable et plus maintenable qu'un bypass générique.

Utiliser le mode spawn (`-f`) plutôt qu'attach chaque fois que la détection pourrait s'exécuter au démarrage. Une détection dans un bloc `static {}` ou dans `attachBaseContext()` sera déjà passée au moment où un attach se connecte.

Commenter chaque hook avec la référence au code source qui a motivé son écriture. Un script non documenté est inutilisable par une autre personne ou lors d'une reprise ultérieure.

Ne jamais laisser un script actif plus longtemps que nécessaire. Détacher Frida après validation et documenter l'état dans lequel l'émulateur a été laissé.

Archiver les scripts dans le dossier du projet avec les versions de Frida utilisées. Un script écrit pour Frida 16.x peut ne pas fonctionner sur Frida 17.x sans modification.

---

## Annexes — Snippets utiles

**Lister toutes les méthodes d'une classe à l'exécution :**

```javascript
Java.perform(function () {
    var TargetClass = Java.use("com.exemple.app.SomeClass");
    var methods = TargetClass.class.getDeclaredMethods();
    methods.forEach(function (m) {
        console.log(m.toString());
    });
});
```

**Tracer tous les appels d'une classe :**

```javascript
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.indexOf("Root") !== -1 || className.indexOf("Detect") !== -1) {
                console.log("[*] Classe suspecte trouvée : " + className);
            }
        },
        onComplete: function () {}
    });
});
```

**Lire la valeur d'un champ statique à l'exécution :**

```javascript
Java.perform(function () {
    var Build = Java.use("android.os.Build");
    console.log("Build.TAGS actuel : " + Build.TAGS.value);
});
```

**Hook d'une méthode native via son symbole exporté :**

```javascript
var moduleBase = Module.findBaseAddress("libcible.so");
if (moduleBase) {
    var targetFunc = Module.findExportByName("libcible.so", "isDeviceRooted");
    if (targetFunc) {
        Interceptor.attach(targetFunc, {
            onLeave: function (retval) {
                console.log("[+] isDeviceRooted natif -> 0");
                retval.replace(0);
            }
        });
    }
}
```

**Obtenir le PID d'une application installée :**

```powershell
adb shell pidof com.exemple.app
```

**Redémarrer frida-server proprement :**

```powershell
.\adb.exe shell "pkill frida-server; sleep 1; /data/local/tmp/frida-server &"
```

---

## Avertissement légal et éthique

Ce laboratoire est conduit dans un cadre pédagogique sur des applications et des environnements contrôlés. Le contournement de mécanismes de protection d'applications sans autorisation explicite constitue une violation des conditions d'utilisation et peut être qualifié d'infraction pénale selon la législation applicable. Les compétences acquises ici sont destinées à la sécurité défensive, à l'audit autorisé, et à la recherche en sécurité.

---

*Laboratoire développé dans le cadre du cours Sécurité des applications mobiles.*
