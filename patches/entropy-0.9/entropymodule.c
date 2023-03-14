#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


static PyObject	*shannon_entropy(PyObject *, PyObject *);

PyDoc_STRVAR(module_doc,
    "Fast entropy calculation.\n"
    "\n"
    "This module provides a method implemented in C for calculating the\n"
    "shannon entropy of a byte string.");

PyDoc_STRVAR(shannon_entropy_doc,
    "shannon_entropy(bytes) -> float\n"
    "\n"
    "H(S) = - Sum(p_i * log(p_i))\n");


static PyMethodDef entropy_methods[] = {
	{"shannon_entropy", shannon_entropy, METH_VARARGS, shannon_entropy_doc},
	{NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef	moduledef = {
	PyModuleDef_HEAD_INIT,
	"entropy",
	module_doc,
	0,
	entropy_methods,
	NULL,
	NULL,
	NULL,
	NULL
};


PyMODINIT_FUNC
PyInit_entropy(void)
{
	return (PyModule_Create(&moduledef));
}
#else
PyMODINIT_FUNC
initentropy(void)
{
	Py_InitModule3("entropy", entropy_methods, module_doc);
}
#endif

static PyObject *
shannon_entropy(PyObject *self, PyObject *args)
{
	const char	*data;
	double		 ent = 0, p;
	size_t		*counts;
#ifdef PYPY_VERSION
	int		 n;
#else
	Py_ssize_t	 n;
#endif
	size_t		 i;

	if (!PyArg_ParseTuple(args, "s#", &data, &n))
		return (NULL);

	if (!(counts = calloc(256, sizeof(*counts))))
		return (PyErr_NoMemory());
	memset(counts, '\0', sizeof(*counts) * 256);

	for (i = 0; i < n; i++)
		counts[(unsigned char)data[i]] += 1;

	for (i = 0; i < 256; i++) {
		if (!counts[i])
			continue;
		p = (double)counts[i] / n;
		ent -= p * logf(p);
	}
	free(counts);

	ent /= logf(256);
	return (Py_BuildValue("d", ent));
}
