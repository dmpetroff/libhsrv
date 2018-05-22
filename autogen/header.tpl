[= AutoGen5 template h gperf =]
[= CASE (suffix) =][=
   == h =][=(dne " *  " "/* ")=]
 */[=
(define (make-name name)
  (let ((cname (get-down-name "id"))
        (reserved '("auto" "if" "break" "int"
					"case" "long" "char" "register"
					"continue" "return" "default" "short"
					"do" "sizeof" "double" "static"
					"else" "struct" "entry" "switch"
					"extern" "typedef" "float" "union"
					"for" "unsigned" "goto" "while"
					"enum" "void" "const" "signed"
					"volatile")))

    (if (member cname reserved)
	  (string-append "hh_" cname)
	  cname)))
(define (hhdr-name name)
  (string-append "HHDR_" (get-up-name name)))
=]
#pragma once
struct http_known_hdr {[=
	FOR header =][=
		IF (not (exist? "internal")) =]
	pstr_t *[=(make-name "id")=];[=
		ENDIF=][=
	ENDFOR header =]
};

enum http_hdr {[=
	FOR header =]
	[=(hhdr-name "id")=],[=
	ENDFOR header =]
};[=

  == gperf =][= (dne " *  " "/* ") =]
 */
%language=ANSI-C
%struct-type
%ignore-case
%define slot-name name
%define hash-function-name http_hdr_hash
%define lookup-function-name http_hdr_find
%compare-strncmp
%readonly-tables
%enum
struct gp_http_hdr { const char *name; enum http_hdr code; int kw_off; };
%%[=
   FOR header =]
[= (string-downcase (get "id")) =], [=
  (hhdr-name "id") =], [=
	IF (exist? "internal") =]0[=
	ELSE =]offsetof(http_request, hh.[= (make-name "id") =])[= ENDIF =][=
   ENDFOR header =][=
   ESAC =]
