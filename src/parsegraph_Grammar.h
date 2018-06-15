#ifndef parsegraph_Grammar_INCLUDED
#define parsegraph_Grammar_INCLUDED

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <ap_config.h>
#include <apr_dbd.h>
#include <mod_dbd.h>
#include "parsegraph_Session.h"
#include "parsegraph_List.h"

parsegraph_ListStatus parsegraph_createGrammar(parsegraph_Session* session, int* grammarId);

#endif // parsegraph_Grammar_INCLUDED
