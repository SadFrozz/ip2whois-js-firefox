chrome.tabs.onActivated.addListener( function(activeInfo){
    chrome.tabs.get(activeInfo.tabId, function(tab){
        y = tab.url;
		$("#search").html("<td>Search</td><td>"+y+"</td>");
        console.log("you are here: "+y);
    });
});

chrome.storage.sync.QUOTA_BYTES = 5242880;
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
    if (tab.active && change.url) {
		$("#search").html("<td>Search</td><td>"+change.url+"</td>");
        console.log("you are here: "+change.url);           
    }
});
function storage_set(key,data,expired=1200) {
	data.expired = Date.now()+expired*1000;
	var string = JSON.stringify(data);
	//console.log("SAVE:"+key);
	chrome.storage.sync.set({[key]: string});
	return true;
}
function isJsonString(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}
function isIPv6(value)
{
  // See https://blogs.msdn.microsoft.com/oldnewthing/20060522-08/?p=31113 and
  // https://4sysops.com/archives/ipv6-tutorial-part-4-ipv6-address-syntax/
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
function bytesToSize(bytes) {
   var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
   if (bytes == 0) return '0 Byte';
   var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
   return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
}
var type = "domain";
function check_domain(check_loc, check_list, counter = 0) {
	$("#ping_results").append("<tr class='loader'><td colspan='3'><div class='uk-text-center'><div uk-spinner></div></div></td></tr>");
	$.get("https://ip2whois.ru/api/traceroute/ping/"+check_loc+"/"+check_list[counter],function(data){
		$(".loader").remove();
		if(data.success) {
			$("#ping_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td>"+data.rtt_statistics.avg.value+" ms<br>"+data.rtt_summary.packets_transmitted+" / "+data.rtt_summary.packets_received+"</td><td>"+data.icmp_sequences[0].target_ip+"</td></tr>");
		} else {
			$("#ping_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td colspan='2'>"+data.message+"</td></tr>");
		}
		if(counter != check_list.length-1) check_domain(check_loc, check_list, counter+1);
	});
}
function check_domain2(check_loc, protocol, check_list, counter = 0) {
	$("#http_results").append("<tr class='loader'><td colspan='3'><div class='uk-text-center'><div uk-spinner></div></div></td></tr>");
	$.post("https://ip2whois.ru/api/traceroute/get/"+check_loc+"/"+check_list[counter],{proto:protocol},function(data){
		$(".loader").remove();
		if(data.success) {
			if(data.http_code == 0) data.http_code = data.http_code + " Failed";
			if(data.http_code == 200) data.http_code = data.http_code + " OK";
			if(data.http_code == 301) data.http_code = data.http_code + " Moved Permanently";
			if(data.http_code == 302) data.http_code = data.http_code + " Found";
			if(data.http_code == 304) data.http_code = data.http_code + " Not Modified";
			if(data.http_code == 307) data.http_code = data.http_code + " Temporary Redirect";
			if(data.http_code == 308) data.http_code = data.http_code + " Permanent Redirect";
			if(data.http_code == 400) data.http_code = data.http_code + " Bad Request";
			if(data.http_code == 401) data.http_code = data.http_code + " Unauthorized";
			if(data.http_code == 403) data.http_code = data.http_code + " Forbidden";
			if(data.http_code == 404) data.http_code = data.http_code + " Not Found";
			if(data.http_code == 500) data.http_code = data.http_code + " Internal Server Error";
			if(data.http_code == 502) data.http_code = data.http_code + " Bad Gateway";
			if(data.http_code == 503) data.http_code = data.http_code + " Service Unavailable";
			if(data.http_code == 504) data.http_code = data.http_code + " Gateway Timeout";
			$("#http_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td>"+data.http_code+"</td><td>"+data.primary_ip+"</td></tr>");
		} else {
			$("#http_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td colspan='2'>"+data.message+"</td></tr>");
		}
		if(counter != check_list.length-1) check_domain2(check_loc, protocol, check_list, counter+1);
	});
}

$('a[data-toggle="tab"]').on('click', function (e) {
  if(e.target.id == "hardware_list-tab") {
	  if($('.hardware_info').html() == "") {
		  chrome.system.cpu.getInfo(function(data) {
			$('.hardware_info').append("<tr><td>Processor:</td><td>"+data.modelName+" x "+data.numOfProcessors+"</td></tr>");
		  });
		  chrome.system.memory.getInfo(function(data) {
			$('.hardware_info').append("<tr><td>Memory:</td><td>total: "+bytesToSize(data.capacity)+"<br/> free: "+bytesToSize(data.availableCapacity)+"</td></tr>");
		  });
		  chrome.system.display.getInfo(function(data) {
			$('.hardware_info').append("<tr><td>Display:</td><td>"+data[0].bounds.width+" x "+data[0].bounds.height+"</td></tr>");
		  });
	  } else {
		  console.log("tab is not null");
	  }
  }
  else if(e.target.id == "ping_list-tab") {
	  $.ajaxSetup({
		   headers:{'Accept': "application/json"}
		});
		if($("#ping_results").html() == "") {
			var host = $("#ping_list-tab").attr("host-name");
			$.get("https://ip2whois.ru/api/testpoints",function(data){
				if(data.success) {
					check_domain(host, data.points, 0);
				}
			});
		}
  }
  else if(e.target.id == "http-tab") {
	  $.ajaxSetup({
		   headers:{'Accept': "application/json"}
		});
		if($("#http_results").html() == "") {
			var host = $("#ping_list-tab").attr("host-name");
			var proto = $("#ping_list-tab").attr("host-proto");
			$.get("https://ip2whois.ru/api/testpoints",function(data){
				if(data.success) {
					check_domain2(host, proto, data.points, 0);
				}
			});
		}
  }
})
chrome.tabs.query({
    active: true,
    lastFocusedWindow: true
}, function(tabs) {
	chrome.storage.sync.get("ip2whois-updated", function(data2) {
		val = data2["ip2whois-updated"];
		if(isJsonString(val)) {
			var cache = JSON.parse(val);
			if(cache.version != manifest.version) {
				$("#update_list-tab").show();
				$("#update").html("New version is availible v "+cache.version+": <a href='"+cache.href+"' target='_blank'><button type='button' class='uk-button uk-button-primary'>Download</button></a>");
				//console.log(cache);
			}
		}
	});
    var tab = tabs[0];
	var proto = tab.url.split(":");
	var manifest = chrome.runtime.getManifest();
	$("#version").html(manifest.version);
	if(proto[0] == "http" || proto[0] == "https") {
		var url = proto[1].split("/");
		url[0] = url[0].replace(":","");
		$("#ping_list-tab").attr("host-name",url[2]);
		$("#ping_list-tab").attr("host-proto",proto[0]);
		$(this).show();
		$("#search").html("<div class='uk-text-center'><div uk-spinner></div></div>");
		if(/^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$/.test(url[2])) {
			try {
				var c_key = url[2].replace(".","_");
				c_key = "ip2whois-"+c_key;
				var val;
				chrome.storage.sync.get(c_key, function(data2) {
						var ip2 = url[2].split(":");
						if(validateIP(ip2[0]) || isIPv6(ip2[0])) {
							type = "ip";
							url[2] = ip2[0];
						} else {
							type = "domain";
						}
					val = data2[c_key];
					if(isJsonString(val)) {
						//console.log("GET:"+c_key);
						var data = JSON.parse(val);
						if(data.expired < Date.now()) {
							chrome.storage.sync.remove([c_key]);
						}
						if(type == "ip") {
							$("#search").html("<a href='https://ip2whois.ru/ip/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
						} else {
							$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
						}
							if(data.success) {
								storage_set(c_key,data);
								if(type == "domain") {
									if(typeof data.domain_utf8 !== "undefined" && data.domain_utf8 != url[2]) {
										$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+data.domain_utf8+"</a>");
									}
								}
								if(typeof data.IPv4 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 4) {
												if($("#IPv4").html() == "") $("#IPv4").append(v.value);
												else $("#IPv4").append("<br>" + v.value);
											}
										});
										if($("#IPv4").html() == "") {
											$("#IPv4").html(data.IPv4);
										}
									} else {
										$("#IPv4").html(data.IPv4);
									}
									if(type == "ip") {
										$(".IPv6").hide();
									}
								}
								else $("#IPv4").html("no info");
								if(typeof data.IPv6 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 6) {
												if($("#IPv6").html() == "") $("#IPv6").append(v.value);
												else $("#IPv6").append("<br>" + v.value);
											}
										});
										if($("#IPv6").html() == "") {
											$("#IPv6").html(data.IPv6);
										}
									} else {
										if(data.IPv6 == "::") {
											$(".IPv6").hide();
										} else $("#IPv6").html(data.IPv6);
									}
									if(type == "ip") {
										$(".IPv4").hide();
									}
								}
								else $("#IPv6").html("no info");
								if(type == "ip") {
									$(".dns").hide();
								} else {
									$.each(data.dns, function(_, v){
										$("#dns").append(v.name + " (" + v.ip + ")<br/>");
									});
								}
								if(typeof data.rank !== "undefined" && data.rank != "") $("#rank").html(data.rank);
								else $(".rank").hide();
								$("#owner").html("<a href='https://ip2whois.ru/asn/"+data.ASN+"' target='_blank'>"+data.ISP+"</a>");
								if(typeof data.ASNimg !== "undefined" && data.ASNimg != "") $("#owner").append(" <img src='"+data.ASNimg+"' style='max-height:32px;max-width:150px'/>");
								$("#ptr").html(data.PTR);
								if(typeof data.ISP_City !== "undefined" && data.rank != "") $("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country + ", " + data.City);
								else $("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country);
							} else {
								$("#IPv4").html("no connection");
								$("#IPv6").html("no connection");
								$("#owner").html("no connection");
								$("#location").html("no connection");
							}
					} else {
						$.get("https://ip2whois.ru/api/whoisinfo/"+type+"/"+url[2], function(data) {
							//console.log(data);
							if(type == "ip") {
								$("#search").html("<a href='https://ip2whois.ru/ip/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
							} else {
								$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
							}
							if(data.success) {
								storage_set(c_key,data);
								if(typeof data.IPv4 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 4) {
												if($("#IPv4").html() == "") $("#IPv4").append(v.value);
												else $("#IPv4").append("<br>" + v.value);
											}
										});
										if($("#IPv4").html() == "") {
											$("#IPv4").html(data.IPv4);
										}
									} else {
										$("#IPv4").html(data.IPv4);
									}
									if(type == "ip") {
										$(".IPv6").hide();
									}
								}
								else $("#IPv4").html("no info");
								if(typeof data.IPv6 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 6) {
												if($("#IPv6").html() == "") $("#IPv6").append(v.value);
												else $("#IPv6").append("<br>" + v.value);
											}
										});
										if($("#IPv6").html() == "") {
											$("#IPv6").html(data.IPv6);
										}
									} else {
										if(data.IPv6 == "::") {
											$(".IPv6").hide();
										} else $("#IPv6").html(data.IPv6);
									}
									if(type == "ip") {
										$(".IPv4").hide();
									}
								}
								else $("#IPv6").html("no info");
								if(type == "ip") {
									$(".dns").hide();
								} else {
									$.each(data.dns, function(_, v){
										$("#dns").append(v.name + " (" + v.ip + ")<br/>");
									});
								}
								if(typeof data.rank !== "undefined" && data.rank != "") $("#rank").html(data.rank);
								else $(".rank").hide();
								$("#owner").html("<a href='https://ip2whois.ru/asn/"+data.ASN+"' target='_blank'>"+data.ISP+"</a>");
								if(typeof data.ASNimg !== "undefined" && data.ASNimg != "") $("#owner").append(" <img src='"+data.ASNimg+"' style='max-height:32px;max-width:150px'/>");
								$("#ptr").html(data.PTR);
								$("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country);
							} else {
								$("#IPv4").html("no connection");
								$("#IPv6").html("no connection");
								$("#owner").html("no connection");
								$("#location").html("no connection");
							}
						});		
					}
				});
						
			}
			catch (e) {
				$("#IPv4").html("no connection");
				$("#IPv6").html("no connection");
				$("#owner").html("no connection");
				$("#location").html("no connection");
				console.log("Error: "+e);
			}
		} else {
			console.log("invalid domain name");
				$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
				$("#IPv4").html("invalid domain name");
				$("#IPv6").html("invalid domain name");
				$("#owner").html("invalid domain name");
				$("#location").html("invalid domain name");
		}
	} else {
		if(proto[0] == "chrome") {
			try {
				$.get("https://ip2whois.ru/api/whoisinfo/ip/my", function(data) {
					//console.log(data);
					if(data.success) {
						
						if(typeof data.IPv4 !== "undefined") {
							$("#IPv4").html(data.IPv4);
							$("#search").html("<a href='https://ip2whois.ru/ip/"+data.IPv4+"' target='_blank'>"+data.IPv4+"</a>");
							$(".IPv6").hide();
						}
						else $("#IPv4").html("no info");
						if(typeof data.IPv6 !== "undefined") {
							$("#IPv6").html(data.IPv6);
							$("#search").html("<a href='https://ip2whois.ru/ip/"+data.IPv6+"' target='_blank'>"+data.IPv6+"</a>");
							$(".IPv4").hide();
						}
						else $("#IPv6").html("no info");
						$(".dns").hide();
						$("#owner").html("<a href='https://ip2whois.ru/asn/"+data.ASN+"' target='_blank'>"+data.ISP+"</a>");
						if(typeof data.ASNimg !== "undefined" && data.ASNimg != "") $("#owner").append(" <img src='"+data.ASNimg+"' height='32' style='max-width:150px'/>");
						$("#ptr").html(data.PTR);
						$("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country);
					} else {
						$("#IPv4").html("no connection");
						$("#IPv6").html("no connection");
						$("#owner").html("no connection");
						$("#location").html("no connection");
					}
				});				
			}
			catch (e) {
				$("#IPv4").html("no connection");
				$("#IPv6").html("no connection");
				$("#owner").html("no connection");
				$("#location").html("no connection");
				console.log("Error: "+e);
			}
		}
	}
});