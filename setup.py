# setup.py
from setuptools import setup
from pybind11.setup_helpers import Pybind11Extension, build_ext

ext = Pybind11Extension(
    "agentmesh._interceptor",
    ["agentmesh/monitor/interceptor.cpp"],
)

setup(
    name="agentmesh",
    ext_modules=[ext],
    cmdclass={"build_ext": build_ext},
)