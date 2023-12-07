# py-plerion
A simple Python-based SDK for the Plerion API.

# Introduction
Plerion is an all-in-one Cloud Security Platform that supports workloads across AWS, Azure, and GCP delivering cloud security posture management, workload security, data security, IAM security, continuous compliance, software bill of materials, shift left security, and more.

# API Reference
The API reference for Plerion can be found [HERE](https://au.app.plerion.com/resources/api-reference) - note that you will need to have an active Plerion login to access this documentation, as it is ***NOT*** publicly available.

# Getting Started
Simply create a `PlerionClient` object, specifying your Plerion API key. Each of the API calls available at the time of publishing this repo are available as functions of the `PlerionClient`.

# Why?
As part of my work, I've been using Plerion to perform scans on IaC code to ensure compliance and security. I had some spare time and figured - why not implement all of the API calls into a collection of Python functions? So, here we are.