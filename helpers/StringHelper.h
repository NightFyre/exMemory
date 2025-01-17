#pragma once
#include <string>

//	Static Class w/ std::string helper methods
class StringHelper
{
public:
	static std::string		ToLower(const std::string& input);
	static std::string		ToUpper(const std::string& input);
	static std::string      ToString(const std::wstring& input);
	static std::wstring     ToWString(const std::string& input);
};