// Copyright 2005-2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include <iostream>
#include <fstream>
#include <filesystem>
#include "ServerConfig.h"

ServerConfig::ServerConfig() { };

bool ServerConfig::checkPath(const std::string &path) {
	std::filesystem::path config_path = path;
	return std::filesystem::exists(config_path);
};

void ServerConfig::createFile(const std::string &path) {
	std::ofstream config;
	config.open(path);
	config << ServerConfig::ini_file;
	config.close();
}

void ServerConfig::createFolder(const std::string &path) {
	std::filesystem::path obj_path = path;
	std::filesystem::create_directory(obj_path);
}
