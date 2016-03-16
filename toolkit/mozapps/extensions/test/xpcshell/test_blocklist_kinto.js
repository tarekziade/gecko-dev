const { classes: Cc, interfaces: Ci, utils: Cu } = Components;

const PREF_BLOCKLIST_VIA_AMO = "security.blocklist.via.amo";
const TEST_APP_ID            = "xpcshell@tests.mozilla.org";
const KEY_PROFILEDIR                  = "ProfD";
const KEY_APPDIR                      = "XCurProcD";
const console = (Cu.import("resource://gre/modules/Console.jsm", {})).console;
const gAppDir = FileUtils.getFile(KEY_APPDIR, []);
const OLD = do_get_file("data/test_blocklist_kinto/old.json");
const NEW = do_get_file("data/test_blocklist_kinto/new.json");
const OLD_TSTAMP = 1296046918000;
const NEW_TSTAMP = 1396046918000;

const SAMPLE_ADDON_RECORD = {
  "prefs": [],
  "blockID": "i446",
  "last_modified": 1457434834683,
  "versionRange": [{
    "targetApplication": [{
      "minVersion": "0.1",
      "guid": "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}",
      "maxVersion": "17.*"
    }],
    "maxVersion": "*",
    "minVersion": "0",
    "severity": "1",
    "vulnerabilityStatus": "0"
  }],
  "guid": "{E90FA778-C2B7-41D0-9FA9-3FEC1CA54D66}",
  "id": "87a5dc56-1fec-ebf2-a09b-6f2cbd4eb2d3"
};

const SAMPLE_PLUGIN_RECORD = {
  "matchFilename": "JavaPlugin2_NPAPI\\.plugin",
  "blockID": "p123",
  "id": "bdcf0717-a873-adbf-7603-83a49fb996bc",
  "last_modified": 1457434851748,
  "versionRange": [{
    "targetApplication": [{
      "minVersion": "0.1",
      "guid": "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}",
      "maxVersion": "17.*"
    }],
    "maxVersion": "14.2.0",
    "minVersion": "0",
    "severity": "1"
  }]
};


function Blocklist() {
  let blocklist = AM_Cc["@mozilla.org/extensions/blocklist;1"].
                  getService().wrappedJSObject;
  return blocklist;
}


function IBlocklist() {
  let blocklist = AM_Cc["@mozilla.org/extensions/blocklist;1"].
                  getService(AM_Ci.nsIBlocklistService);
  return blocklist;
}


function run_test() {
  // Some blocklist code rely on gApp.ID.
  createAppInfo(TEST_APP_ID, "XPCShell", "1", "1");
  // Disable blocklist via AMO.
  Services.prefs.setBoolPref(PREF_BLOCKLIST_VIA_AMO, false);


  run_next_test();
}


add_task(function* test_addon_entry_from_json_simple() {
  const blocklist = Blocklist();
  const data = Object.assign({}, SAMPLE_ADDON_RECORD);

  const entry = blocklist._handleAddonItemJSON(data);

  do_check_eq(entry.blockID, SAMPLE_ADDON_RECORD.blockID);
  do_check_eq(entry.prefs, SAMPLE_ADDON_RECORD.prefs);
  do_check_eq(entry.attributes.get("id"), SAMPLE_ADDON_RECORD.guid);
  do_check_eq(entry.versions.length, 1);
  const item = entry.versions[0];
  do_check_eq(item.minVersion, "0");
  do_check_eq(item.maxVersion, "*");
  do_check_eq(item.severity, "1");
  do_check_eq(item.vulnerabilityStatus, "0");
  do_check_eq(item.targetApps["{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"].minVersion, "0.1");
  do_check_eq(item.targetApps["{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"].maxVersion, "17.*");
});


add_task(function* test_addon_entry_from_json_no_version_range() {
  const blocklist = Blocklist();
  const data = Object.assign({}, SAMPLE_ADDON_RECORD);
  data.versionRange = [];

  const entry = blocklist._handleAddonItemJSON(data);

  do_check_eq(entry.versions.length, 1);
  const item = entry.versions[0];
  do_check_eq(item.minVersion, null);
  do_check_eq(item.maxVersion, null);
  do_check_eq(item.severity, 3);
  do_check_eq(item.vulnerabilityStatus, 0);
  do_check_eq(item.targetApps[TEST_APP_ID].minVersion, null);
  do_check_eq(item.targetApps[TEST_APP_ID].maxVersion, null);
});


add_task(function* test_addon_entry_from_json_without_blockid() {
  const blocklist = Blocklist();
  const data = Object.assign({}, SAMPLE_ADDON_RECORD);
  delete data.blockID;

  const entry = blocklist._handleAddonItemJSON(data);

  do_check_eq(entry.blockID, SAMPLE_ADDON_RECORD.id);
});


/*
add_task(function* test_plugin_entry_from_json_simple() {
  const blocklist = Blocklist();
  const data = Object.assign({}, SAMPLE_PLUGIN_RECORD);

  const entry = blocklist._handlePluginItemJSON(data);

  do_check_eq(entry.blockID, SAMPLE_PLUGIN_RECORD.blockID);
  do_check_eq(entry.infoURL, SAMPLE_PLUGIN_RECORD.infoURL);
  do_check_eq(entry.matches['filename'].constructor.name, "RegExp");
  do_check_eq(entry.versions.length, 1);
  const item = entry.versions[0];
  do_check_eq(item.minVersion, "0");
  do_check_eq(item.maxVersion, "14.2.0");
  do_check_eq(item.severity, "1");
  do_check_eq(item.targetApps["{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"].minVersion, "0.1");
  do_check_eq(item.targetApps["{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"].maxVersion, "17.*");
});
*/

add_task(function* test_plugin_entry_from_json_no_match() {
  const blocklist = Blocklist();
  const data = Object.assign({}, SAMPLE_PLUGIN_RECORD);
  delete data.matchFilename;

  const entry = blocklist._handlePluginItemJSON(data);

  do_check_eq(entry, undefined);
});


add_task(function* test_plugin_entry_from_json_no_version_range() {
  const blocklist = Blocklist();
  const data = Object.assign({}, SAMPLE_PLUGIN_RECORD);
  data.versionRange = [];

  const entry = blocklist._handlePluginItemJSON(data);

  do_check_eq(entry.versions.length, 1);
  const item = entry.versions[0];
  do_check_eq(item.minVersion, null);
  do_check_eq(item.maxVersion, null);
  do_check_eq(item.severity, 3);
  do_check_eq(item.targetApps[TEST_APP_ID].minVersion, null);
  do_check_eq(item.targetApps[TEST_APP_ID].maxVersion, null);
});


add_task(function* test_plugin_entry_from_json_without_blockid() {
  const blocklist = Blocklist();
  const data = Object.assign({}, SAMPLE_PLUGIN_RECORD);
  delete data.blockID;

  const entry = blocklist._handlePluginItemJSON(data);

  do_check_eq(entry.blockID, SAMPLE_PLUGIN_RECORD.id);
});


add_task(function* test_is_loaded_synchronously() {
  const blocklist = Blocklist();
  do_check_false(blocklist._isBlocklistLoaded());
  blocklist.isAddonBlocklisted("addon", "appVersion", "toolkitVersion");
  do_check_true(blocklist._isBlocklistLoaded());
});


/* XXX need to unpatch
add_task(function* test_relies_on_handle_json_methods() {
  copyToApp(OLD, "addons");
  const blocklist = Blocklist();
  const sample = {sentinel: true};
  blocklist._handleAddonItemJSON = () => sample;
  blocklist._handlePluginItemJSON = () => sample;

  blocklist._loadBlocklist();

  do_check_eq(blocklist._addonEntries[0], sample);
  do_check_eq(blocklist._pluginEntries[0], sample);
});
*/

// add_test(function* test_notify_does_not_download_xml_file() {
//   const blocklist = IBlocklist();

//   // XXX: This hangs!
//   blocklist.notify();

//   // When blocklist is managed via AMO, it is loaded on notify()
//   // before being downloaded.
//   do_check_false(blocklist._isBlocklistLoaded());
// });


// name can be addons or plugins
function clearBlocklists(name) {
  let filename = "blocklist-" + name + ".json";
  let blocklist = FileUtils.getFile(KEY_APPDIR, [filename]);
  if (blocklist.exists())
    blocklist.remove(true);

  blocklist = FileUtils.getFile(KEY_PROFILEDIR, [filename]);
  if (blocklist.exists())
    blocklist.remove(true);
}

function reloadBlocklist() {
  Services.prefs.setBoolPref(PREF_BLOCKLIST_ENABLED, false);
  Services.prefs.setBoolPref(PREF_BLOCKLIST_ENABLED, true);
}

function copyToApp(file, name) {
  let filename = "blocklist-" + name + ".json";
  file.clone().copyTo(gAppDir, filename);
}

function copyToProfile(file, tstamp, name) {
  let filename = "blocklist-" + name + ".json";
  file = file.clone();
  file.copyTo(gProfD, filename);
  file = gProfD.clone();
  file.append(filename);
  file.lastModifiedTime = tstamp;
}



add_task(function* test_read_json_from_app_or_profile() {
  const blocklist = Blocklist();
  blocklist._loadBlocklist();
  do_check_eq(blocklist._addonEntries.length, 416);

  clearBlocklists("addons");
  copyToApp(OLD, "addons");
  copyToProfile(NEW, NEW_TSTAMP, "addons");

  blocklist._loadBlocklist();

  // we should have one more
  do_check_eq(blocklist._addonEntries.length, 417);


  // addon in app  / plugins in app
  // addon in prof / plugins in app
  // addon in app  / plugins in prof
  // addon in prof / plugins in prof
  // 
});


// add_test(function* test_invalid_json() {
// });

// add_test(function* preload_json_async() {
//   // addon async / plugins sync
//   // addon sync  / plugins sync
//   // addon async / plugins async
//   // addon sync  / plugins async
// });

