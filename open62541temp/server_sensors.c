/* Server demo example. Which scans all available sensors by lm-sensors and register their
 * values in OPC nodes. Read callback is set for data update. 
 */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS /* disable fopen deprication warning in msvs */
#endif

#include "open62541.h"
#include "common.h"
#include <signal.h>
#include <sensors/sensors.h>


static const UA_NodeId baseDataVariableType = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_BASEDATAVARIABLETYPE}};
static const UA_NodeId accessDenied = {1, UA_NODEIDTYPE_NUMERIC, {1337}};

UA_Boolean running = true;

typedef struct {
	const sensors_chip_name *name;
	int subfeat_nr;
} req_sensors_t;


static void stopHandler(int sign) {
	UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Received Ctrl-C");
	running = 0;
}

/* Custom AccessControl policy that disallows access to one specific node */
static UA_Byte
getUserAccessLevel_disallowSpecific(UA_Server *server, UA_AccessControl *ac,
				    const UA_NodeId *sessionId, void *sessionContext,
				    const UA_NodeId *nodeId, void *nodeContext)
{
	if (UA_NodeId_equal(nodeId, &accessDenied))
		return 0x00;
	return 0xFF;
}

static UA_StatusCode read_sensor_value(UA_Server *server,
				       const UA_NodeId *sessionId,
				       void *sessionContext,
				       const UA_NodeId *nodeId,
				       void *nodeContext,
				       UA_Boolean sourceTimeStamp,
				       const UA_NumericRange *range,
				       UA_DataValue *value)
{
	UA_DateTime currentTime; 
	req_sensors_t *req_sensors = (req_sensors_t *)nodeContext;
	double val;
	int rc;

	if (range) {
		value->hasStatus = true;
		value->status = UA_STATUSCODE_BADINDEXRANGEINVALID;
		return UA_STATUSCODE_GOOD;
	}

	rc = sensors_get_value(req_sensors->name, req_sensors->subfeat_nr, &val);
	if (rc < 0) {
		fprintf(stderr, "can not read value %s (%s) nr %d\n",
			req_sensors->name->prefix,
			req_sensors->name->path,
			req_sensors->subfeat_nr);
		value->hasValue = false;
		return UA_STATUSCODE_GOOD;
	}

	UA_Variant_setScalarCopy(&value->value, &val, &UA_TYPES[UA_TYPES_DOUBLE]);
	value->hasValue = true;

	if (sourceTimeStamp) {
		UA_DateTime now = UA_DateTime_now();
	
		value->hasSourceTimestamp = true;
		value->sourceTimestamp = now;
	}
	
	fprintf(stdout, "debug read: %s (%s) nr %d value %f\n",
			req_sensors->name->prefix,
			req_sensors->name->path,
			req_sensors->subfeat_nr,
			val);

	return UA_STATUSCODE_GOOD;
}

static int register_node_sensor(UA_Server *server,
				sensors_chip_name const *cn,
				sensors_feature const *feat,
				sensors_subfeature const *subf)
{
	UA_DataSource dateDataSource;
	UA_VariableAttributes v_attr;
	UA_QualifiedName qName;
	UA_NodeId NodeId;
	char sensor_name[30];
	void *nodeContext;
	req_sensors_t *req_sensors;

	snprintf(sensor_name, 30, "%s_%s", cn->prefix, subf->name);

	req_sensors = malloc(sizeof(req_sensors_t));
	if (!req_sensors) {
		fprintf(stderr, "unable to allocate req_sensors_t\n");
		return -1;
	}

	req_sensors->name = cn;
	req_sensors->subfeat_nr = subf->number;
	nodeContext = (void *)req_sensors;

	qName = UA_QUALIFIEDNAME(1, sensor_name);
	NodeId = UA_NODEID_STRING(1, sensor_name);
	printf("%s: at node1 %s\n", __func__, sensor_name);

	dateDataSource.read = read_sensor_value;
	dateDataSource.write = NULL;

	v_attr = UA_VariableAttributes_default;
	v_attr.description = UA_LOCALIZEDTEXT("en-US", cn->prefix);
	v_attr.displayName = UA_LOCALIZEDTEXT("en-US", cn->prefix);
	v_attr.accessLevel = UA_ACCESSLEVELMASK_READ;
	v_attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
	v_attr.valueRank = UA_VALUERANK_SCALAR;

	UA_Server_addDataSourceVariableNode(server,
			NodeId, /* requestedNewNodeId */
			UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), /* parentNodeId */
			UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), /* referencedTypeId */
			qName, /* browseName */
			baseDataVariableType, /* typeDefinition */
			v_attr,
			dateDataSource,
			nodeContext,
			NULL /* outNewNodeId */);
	return 0;
}

/* Discover all available sensors and register them */
static int register_sensors(UA_Server *server) {
	sensors_chip_name const *cn;
	int c = 0;
	int rc;
	
	rc = sensors_init(NULL);
	if (rc) {
		printf("can not sensors_init rc: %d\n", rc);
		return -1;
	}

	while (1) {
		int f = 0;

		cn = sensors_get_detected_chips(0, &c);
		if (cn == NULL)
			break;

		while (1) {
			sensors_feature const *feat;
			int s = 0;

			feat = sensors_get_features(cn, &f);
			if (!feat)
				break;

			while (1) {
				double val;
				sensors_subfeature const *subf;

				subf = sensors_get_all_subfeatures(cn, feat, &s);
				if (!subf)
					break;

				rc = register_node_sensor(server, cn, feat, subf);
				if (rc) {
					fprintf(stderr, "bug, unable to registed sensor\n");
					return rc;
				}
			}
		}
	}

	return 0;
}

int main(int argc, char **argv) {
	signal(SIGINT, stopHandler); /* catches ctrl-c */
	signal(SIGTERM, stopHandler);

	UA_ServerConfig *config;
#ifdef UA_ENABLE_ENCRYPTION
	if(argc < 3) {
		UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
				"Missing arguments for encryption support. "
				"Arguments are <server-certificate.der> "
				"<private-key.der> [<trustlist1.crl>, ...]");
		config = UA_ServerConfig_new_minimal(4840, NULL);
	} else {
		/* Load certificate and private key */
		UA_ByteString certificate = loadFile(argv[1]);
		if(certificate.length == 0) {
			UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
					"Unable to load file %s.", argv[1]);
			return 1;
		}
		UA_ByteString privateKey = loadFile(argv[2]);
		if(privateKey.length == 0) {
			UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
					"Unable to load file %s.", argv[2]);
			return 1;
		}

		/* Load the trustlist */
		size_t trustListSize = 0;
		if(argc > 3)
			trustListSize = (size_t)argc-3;
		UA_STACKARRAY(UA_ByteString, trustList, trustListSize);
		for(size_t i = 0; i < trustListSize; i++)
			trustList[i] = loadFile(argv[i+3]);

		/* Loading of a revocation list currently unsupported */
		UA_ByteString *revocationList = NULL;
		size_t revocationListSize = 0;

		config = UA_ServerConfig_new_allSecurityPolicies(4840, &certificate, &privateKey,
				trustList, trustListSize,
				revocationList, revocationListSize);
		UA_ByteString_deleteMembers(&certificate);
		UA_ByteString_deleteMembers(&privateKey);
		for(size_t i = 0; i < trustListSize; i++)
			UA_ByteString_deleteMembers(&trustList[i]);
	}
#else
	UA_ByteString certificate = UA_BYTESTRING_NULL;
	if(argc < 2) {
		UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
				"Missing argument for the server certificate");
	} else {
		certificate = loadFile(argv[1]);
	}
	config = UA_ServerConfig_new_minimal(4840, &certificate);
	UA_ByteString_deleteMembers(&certificate);
#endif

	if(!config) {
		UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
				"Could not create the server config");
		return 1;
	}

	/* Override with a custom access control policy */
	config->accessControl.getUserAccessLevel = getUserAccessLevel_disallowSpecific;

	/* uncomment next line to add a custom hostname */
	// UA_ServerConfig_set_customHostname(config, UA_STRING("custom"));

	UA_Server *server = UA_Server_new(config);
	if (server == NULL)
		return 1;

	register_sensors(server);

	/* run server */
	UA_StatusCode retval = UA_Server_run(server, &running);
	UA_Server_delete(server);
	UA_ServerConfig_delete(config);
	return (int)retval;
}
