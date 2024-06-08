/*
This is alpha version. Some shit in code. Fixes may be later.
*/

chrome.tabs.onActivated.addListener( function(activeInfo){
    chrome.tabs.get(activeInfo.tabId, function(tab){
        var y = tab.url;
		changeIco(y);    
    });
});

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
    if (tab.active && change.url) {
		changeIco(change.url);  
    }
});
var updated = false;
chrome.storage.sync.QUOTA_BYTES = 5242880;
function sendRequest(url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            callback(xhr.responseText);
        }
    };
    xhr.open("GET", url, true);
    xhr.send();
}
function updater() {
		var val;
		var manifest = chrome.runtime.getManifest();
		chrome.storage.sync.get("ip2whois-updated", function(data2) {
			val = data2["ip2whois-updated"];
			if(isJsonString(val)) {
				var cache = JSON.parse(val);
				if(cache.expired < Date.now()) {
					chrome.storage.sync.remove("ip2whois-updated");
					//console.log("DELETE CACHE: ip2whois-updated");
				}
				if(cache.version != manifest.version) {
									chrome.action.setBadgeText(
									  {
										text: "!",
									  },
									  () => {}
									);
					updated = true;
				} else {
					chrome.action.getBadgeText({}, function(result) {
						if(result != "") {
									chrome.action.setBadgeText(
									  {
										text: "",
									  },
									  () => {}
									);
						}
					});
					updated = true;
				}
			} else {
						fetch("https://ip2whois.ru/api/latest").then((response) => {
							return response.json();
						})
						.then((data) => {
							if(data.success){
								if(data.version != manifest.version) {
									chrome.action.setBadgeText(
									  {
										text: "!",
									  },
									  () => {}
									);
								}
								chrome.action.getBadgeText({}, function(result) {
									if(result != "") {
												chrome.action.setBadgeText(
												  {
													text: "",
												  },
												  () => {}
												);
									}
								});
								storage_set("ip2whois-updated",data);
							}
							updated = true;
						});
			}
		});
	console.log("Check updates!");
	setTimeout(function() {updater();},1800000);
}
updater();
function isJsonString(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}
function storage_get(key) {
	key = "ip2whois-"+key;
	var val;
	chrome.storage.sync.get(key, function(data) {
		val = data[key];
		if(isJsonString(val)) {
			var cache = JSON.parse(val);
			if(cache.expired > Date.now()) {
				chrome.storage.sync.remove([key]);
				return false;
			} else {
				//console.log(cache);
				return cache;
			}
		} else {
			//console.log("failed:");
			return false;
		}
	});
}
function storage_set(key,data,expired=1200) {
	data.expired = Date.now()+expired*1000;
	var string = JSON.stringify(data);
	//console.log("SAVE:"+key);
	chrome.storage.sync.set({[key]: string});
	return true;
}
function isIPv6(value)
{
  const components = value.split(":");
  if (components.length < 2 || components.length > 8)
    return false;
  if (components[0] !== "" || components[1] !== "")
  {
    // Address does not begin with a zero compression ("::")
    if (!components[0].match(/^[\da-f]{1,4}/i))
    {
      // Component must contain 1-4 hex characters
      return false;
    }
  }

  let numberOfZeroCompressions = 0;
  for (let i = 1; i < components.length; ++i)
  {
    if (components[i] === "")
    {
      // We're inside a zero compression ("::")
      ++numberOfZeroCompressions;
      if (numberOfZeroCompressions > 1)
      {
        // Zero compression can only occur once in an address
        return false;
      }
      continue;
    }
    if (!components[i].match(/^[\da-f]{1,4}/i))
    {
      // Component must contain 1-4 hex characters
      return false;
    }
  }
  return true;
}
function validateIP(ip) {
    var is_valid = false;
    ip = ip.replace(/\s+/, "");

    if(ip.indexOf('/')!=-1){
        return false
    }
    
    try {
        var ipb = ip.split('.');
        if (ipb.length == 4) {
            for (var i = 0; i < ipb.length; i++) {
                var b = parseInt(ipb[i]);    
                if (b >= 0 && b <= 255) {
                    is_valid = true;
                } else {
                    is_valid = false;
                    break;
                }
            }
        }
    } catch (exception) {
        return false;
    }
    if (!is_valid) {
        return false;
    }
    return true;
}
var type = "domain";
var tryes = 0;
function changeIco(links) {
	if(!updated) {
	}
	var proto = links.split(":");
	if(proto[0] == "http" || proto[0] == "https") {
		var url = proto[1].split("/");
		if(/^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$/.test(url[2])) {
			try	{
				var c_key = url[2].replace(".","_");
				c_key = "ip2whois-"+c_key;
				var val;
				chrome.storage.sync.get(c_key, function(data) {
					val = data[c_key];
					if(isJsonString(val)) {
						//console.log("GET:"+c_key);
						var cache = JSON.parse(val);
						if(cache.expired < Date.now()) {
							chrome.storage.sync.remove([c_key]);
							//console.log("DELETE CACHE: "+c_key);
							changeIco(links);
						} else {
							chrome.action.setIcon({path: {"128": cache.img }});
						}
					} else {
						var ip2 = url[2].split(":");
						if(validateIP(ip2[0]) || isIPv6(ip2[0])) {
							type = "ip";
							url[2] = ip2[0];
						} else {
							type = "domain";
						}
						fetch("https://ip2whois.ru/api/whoisinfo/"+type+"/"+url[2])
						.then((response) => {
							return response.text();
						})
						.then((response) => {
							if(isJsonString(response)) {
								return JSON.parse(response);
							} else {
								console.log("failed to fetch "+url[2]+" with result: "+response);
								if(tryes < 5) {
									setTimeout(function() {changeIco(links);},1000);
									tryes += 1;
								} else {
									console.log("Max tryes reached! Fail to get info!");
									tryes = 0;
								}
								return null;
							}
						})
						.then((data) => {
							//console.log(data);
							if(data != null && data.success){
								storage_set(c_key,data);
								chrome.action.setIcon({path: {"128": data.img }});
							}
							else chrome.action.setIcon({path: {"128": "images/icon128.png" }});  
						});
					}
				});
			}
			catch(e) {
				chrome.action.setIcon({path: {"128": "images/icon128.png" }});  
				console.log("error caching " +e);
			}
		} else {
			console.log("invalid domain name");
			//console.log(url);
		}
	} else {
		if(proto[0] == "chrome") {
			try	{
				var c_key = proto[0].replace(":","");
				
				c_key = "ip2whois-"+c_key;
				var val;
				chrome.storage.sync.get(c_key, function(data) {
					val = data[c_key];
					if(isJsonString(val)) {
						//console.log("GET:"+c_key);
						var cache = JSON.parse(val);
						if(cache.expired < Date.now()) {
							chrome.storage.sync.remove([c_key]);
							//console.log("DELETE CACHE: "+c_key);
							changeIco(links);
						} else {
							chrome.action.setIcon({path: {"512": cache.img }});
						}
					} else {
						fetch("https://ip2whois.ru/api/whoisinfo/ip/my").then((response) => {
							return response.json();
						})
						.then((data) => {
							//console.log(data);
							if(data.success){
								storage_set(c_key,data);
								chrome.action.setIcon({path: {"512": data.img }});
							}
							else chrome.action.setIcon({path: {"512": "ip2whois.png" }});  
						});
					}
				});
			}
			catch(e) {
				chrome.action.setIcon({path: {"512": "ip2whois.png" }});  
				console.log("error caching " +e);
			}
		}
	}
}