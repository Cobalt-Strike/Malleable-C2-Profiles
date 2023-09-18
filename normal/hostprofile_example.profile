#
# Host Profile example profile
# 
# Author: Cobalt Strike team
#

set host_stage            "false";
set sleeptime             "3000";

# --------------------------------------------------------------------------------------
# Some fields in "http-host-profiles" group support a dynamic value syntax
# --------------------------------------------------------------------------------------
# Beacons will randomly select one of the optional values in the specified dynamic syntax.
# Dynamic syntax is wrapped by square brackets with values separated by "|".
#
# Dynamic syntax can be an entire value.
#   Example:   [example.abc|sample.def|demo.ghi]
#   Resolves:  example.abc
#              sample.def
#              demo.ghi
#
# Dynamic syntax can be embedded in static text.
#   Example:   prefix/[a|b]/suffix
#   Resolves:  prefix/a/suffix
#              prefix/b/suffix
#
# Dynamic syntax can have one or more blank options as a selected value.
#   Example:   abc/folder[1||3|]/xyz
#   Resolves:  abc/folder1/xyz
#              abc/folder/xyz
#              abc/folder3/xyz
#              abc/folder/xyz
#
# Dynamic syntax can have multiple dynamic items.
#   Example:   [abc|xyz]/[123|456]/[index.html|hello.js|home.jsp]
#
# Restrictions:
#   Up to 8 host profiles used per listener/beacon
#   1024 byte limit on space for all profiles used in a beacon (use small simple definitions if possible)
#   Maximum tokens in a dynamic field: 32
#   Maximum get/post headers/parameters in a host profile: 10 each
#
# Warning:
#   Extreme dynamic data can cause linting to run long and possibly fail checking for URI collision...
#   Example:   [1|2|3|...|30|31|32]--[1|2|3|...|30|31|32]--[1|2|3|...|30|31|32]...
# --------------------------------------------------------------------------------------

http-host-profiles {
	# The "http-host-profiles" section can contain one or more profile definitions...
	profile {
		# Each host "http-host-profiles.profile" must have a unique "host-name" specified.
		# The "http-host-profiles.host-name" should exactly match up with host name(s) specified on host name list of HTTP(S) listeners.
		# Attributes defined in the host profile will be used in beacons on matching callback host names.
		# HOST NAME DOES NOT SUPPORT DYNAMIC SYNTAX.
		set             host-name                        "example.yyy";

		# Define "http-get" attributes...
		http-get {
			# The uri can be OVERRIDDEN.
			set         uri                              "/get/example/[index.html|hello.js|home.jsp]";
			# set       uri                              "/[abc|xyz]/[abc|xyz].[js|jsp|html|jpg|svg]";
			# set       uri                              "/example/home.html";

			# Headers can be ADDED to the existing definition.
			# Header names resolved to blank will be dropped.
			# Header values resolved to blank will be dropped.
			header      "gh1"                            "[a|b|c]";
			header      "gh[2|3|4]"                      "static";
			header      "[gh5||gh7]"                     "dropped-one-third";
			header      "gh[8|9]"                        "value-[1|2]";

			# Parameters can be ADDED to the existing definition.
			# Parameter names resolved to blank will be dropped.
			# Parameter values resolved to blank are supported.
			parameter   "wiki-lookup"                    "[cobol|java|c|javascript|rpg|cl|python]";
			parameter   "wiki-user"                      "Good Person";
			parameter   "wiki-user2"                     "[Neo|Morpheus|Cypher|Trinity|Agent] [Anderson|Smith]";
			parameter   "gp1"                            "[a|b|c]";
			parameter   "gp[2|3|4]"                      "static";
			parameter   "[gp5||gp7]"                     "dropped-one-third";
			parameter   "gp[8|9]"                        "value-[1|2]";
		}

		# Define "http-post" attributes.
		http-post {
			set         uri                              "/post/example/[index.html|hello.js|home.jsp]";

			header      "ph1"                            "[a|b|c]";
			header      "ph[2|3|4]"                      "static";
			header      "[ph5||ph7]"                     "dropped-one-third";
			header      "ph[8|9]"                        "value-[1|2]";

			parameter   "pp1"                            "[a|b|c]";
			parameter   "pp[2|3|4]"                      "static";
			parameter   "[pp5||pp7]"                     "dropped-one-third";
			parameter   "pp[8|9]"                        "value-[1|2]";
		}
	}

	# Second profile example...
	profile {
		set             host-name                        "second.yyy";
		http-get {
			set         uri                              "/get/second/a.[html|php|jsp]";
			header      "second-gh"                      "[a|b|c]";
			parameter   "second-gp"                      "[a|b|c]";
		}
		http-post {
			set         uri                              "/post/second/b.[html|php|jsp]";
			header      "second-ph"                      "[a|b|c]";
			parameter   "second-pp"                      "[a|b|c]";
		}
	}
}

# =======================================================================================
# default profile...
# =======================================================================================
http-get {
	set                 uri                              "/dft/get/uri.aaa /dft/get/uri.bbb /dft/get/uri.ccc";
	set                 verb                             "POST"; # GET|POST
	client {
		header          "dft-gch"                        "gch1";
		parameter       "dft-gcp"                        "gcp1";
		metadata {
			# mask;
			base64url;
			print; # REQUIRES POST VERB ###
		}
	}
	server {
		header          "dft-gsh"                        "gsh2";
		output {
			# mask;
			base64url;
			print;
		}
	}
}

http-post {
	set                 uri                              "/dft/post/uri.aaa /dft/post/uri.bbb /dft/post/uri.ccc";
	set                 verb                             "POST"; # GET|POST
	client {
		header          "dft-pch"                        "pch3";
		parameter       "dft-pcp"                        "pcp3";
		id {
			# mask;
			base64url;
			parameter                                    "dft-pcp-id";
		}
		output {
			# mask;
			base64url;
			print; ### REQUIRES POST VERB ###
		}
	}
	server {
		header          "dft-psh"                        "psh4";
		output {
			# mask;
			base64url;
			print;
		}
	}
}



