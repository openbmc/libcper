#if LIBCPER_PYTHON
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <libcper/cper-parse-str.h>
#include <libcper/cper-parse.h>

PyObject *convert_to_pydict(json_object *jso)
{
	PyObject *ret = Py_None;
	enum json_type type = json_object_get_type(jso);
	//printf("type: %d ", type);
	switch (type) {
	case json_type_null:
		//printf("json_type_null\n");
		ret = Py_None;
		break;
	case json_type_boolean: {
		//printf("json_type_boolean\n");
		int b = json_object_get_boolean(jso);
		ret = PyBool_FromLong(b);
	} break;
	case json_type_double: {
		//printf("json_type_double\n");
		double d = json_object_get_double(jso);
		ret = PyFloat_FromDouble(d);
	} break;

	case json_type_int: {
		//printf("json_type_int\n");
		int64_t i = json_object_get_int64(jso);
		ret = PyLong_FromLong(i);
	} break;
	case json_type_object: {
		//printf("json_type_object\n");
		ret = PyDict_New();

		json_object_object_foreach(jso, key1, val)
		{
			PyObject *pyobj = convert_to_pydict(val);
			if (key1 != NULL) {
				//printf("Parsing %s\n", key1);
				if (pyobj == NULL) {
					pyobj = Py_None;
				}
				PyDict_SetItemString(ret, key1, pyobj);
			}
		}
	} break;
	case json_type_array: {
		//printf("json_type_array\n");
		ret = PyList_New(0);
		int arraylen = json_object_array_length(jso);

		for (int i = 0; i < arraylen; i++) {
			//printf("Parsing %d\n", i);
			json_object *val = json_object_array_get_idx(jso, i);
			PyObject *pyobj = convert_to_pydict(val);
			if (pyobj == NULL) {
				pyobj = Py_None;
			}
			PyList_Append(ret, pyobj);
		}
	} break;
	case json_type_string: {
		//printf("json_type_string\n");
		const char *strval = json_object_get_string(jso);
		ret = PyUnicode_FromString(strval);
	} break;
	}
	return ret;
}

static PyObject *parse(PyObject *self, PyObject *args)
{
	(void)self;
	PyObject *ret;
	const unsigned char *data;
	Py_ssize_t count;

	if (!PyArg_ParseTuple(args, "y#", &data, &count)) {
		return NULL;
	}

	char *jstrout = cperbuf_to_str_ir(data, count);
	if (jstrout == NULL) {
		free(jstrout);
		return NULL;
	}
	json_object *jout = cper_buf_to_ir(data, count);
	if (jout == NULL) {
		free(jstrout);
		free(jout);
		return NULL;
	}

	ret = convert_to_pydict(jout);

	//ret = PyUnicode_FromString(jstrout);
	free(jout);
	free(jstrout);
	return ret;
}

static PyMethodDef methods[] = {
	{ "parse", (PyCFunction)parse, METH_VARARGS, NULL },
	{ NULL, NULL, 0, NULL },
};

static struct PyModuleDef module = {
	PyModuleDef_HEAD_INIT,
	"cper",
	NULL,
	-1,
	methods,
	NULL,
	NULL,
	NULL,
	NULL,
};

PyMODINIT_FUNC PyInit_cper(void)
{
	return PyModule_Create(&module);
}
#endif
