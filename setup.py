# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="jupyterhub-gcp-proxies-authenticator",
    python_requires='>=3.6.0',
    version="0.1.0",
    author="Matthieu Mayran",
    author_email="mayran@google.com",
    description="JupyterHub authenticator for Cloud IAP and Inverting Proxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GoogleCloudPlatform/jupyterhub-gcp-proxies-authenticator",
    packages=setuptools.find_packages(),
    license='Apache 2.0',
    install_requires=[
        "jupyterhub", 
        "tornado>=5.0",
        'oauthenticator>=0.9.0',
        'pyjwt>=1.7.1'
    ]
)