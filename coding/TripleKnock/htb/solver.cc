#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

// Convert timestamp "DD/MM HH:MM" to total minutes since day 0
int total_minutes(const std::string& timestamp) {
    int day, month, hour, minute;
    sscanf(timestamp.c_str(), "%d/%d %d:%d", &day, &month, &hour, &minute);
    int days = (month - 1) * 30 + day - 1;
    return (days * 24 * 60) + (hour * 60) + minute;
}

int main() {
    int S, N;
    std::cin >> S >> N;
    std::cin.ignore(); // consume the newline after the first line

    std::unordered_map<std::string, std::vector<int>> user_times;

    for (int i = 0; i < S; ++i) {
        std::string line;
        std::getline(std::cin, line);

        if (line.find("[failure]") == std::string::npos) continue;

        size_t bracket_pos = line.find("[");
        std::string log_entry = line.substr(0, bracket_pos - 1); // trim trailing space
        std::istringstream iss(log_entry);
        std::string user, date, time;
        iss >> user >> date >> time;

        std::string timestamp = date + " " + time;
        user_times[user].push_back(total_minutes(timestamp));
    }

    std::vector<int> targeted_ids;

    for (auto& [user, times] : user_times) {
        std::sort(times.begin(), times.end());
        for (size_t i = 0; i + 2 < times.size(); ++i) {
            if (times[i + 2] - times[i] <= 10) {
                int id = std::stoi(user.substr(5)); // assumes user format "user_X"
                targeted_ids.push_back(id);
                break;
            }
        }
    }

    std::sort(targeted_ids.begin(), targeted_ids.end());

    for (size_t i = 0; i < targeted_ids.size(); ++i) {
        if (i > 0) std::cout << " ";
        std::cout << "user_" << targeted_ids[i];
    }
    std::cout << std::endl;

    return 0;
}