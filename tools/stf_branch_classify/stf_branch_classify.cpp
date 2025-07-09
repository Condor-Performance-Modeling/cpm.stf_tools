#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <algorithm>

#include "print_utils.hpp"
#include "stf_branch_reader.hpp"
#include "command_line_parser.hpp"

void processCommandLine(int argc,
                        char** argv,
                        std::string& trace,
                        bool& verbose,
                        bool& only_taken,
                        bool& only_dynamic,
                        bool& skip_non_user) {
    trace_tools::CommandLineParser parser("stf_branch_classify");
    parser.addFlag('v', "verbose mode (prints indirect branch targets)");
    parser.addFlag('t', "only report taken branches (branches that are taken at least once)");
    parser.addFlag('d', "only report dynamic branches (branches that are not always-taken or never-taken)");
    parser.addFlag('u', "skip non user-mode instructions");
    parser.addPositionalArgument("trace", "trace in STF format");
    parser.parseArguments(argc, argv);
    verbose = parser.hasArgument('v');
    only_taken = parser.hasArgument('t');
    only_dynamic = parser.hasArgument('d');
    skip_non_user = parser.hasArgument('u');

    parser.getPositionalArgument(0, trace);
}

enum class Direction : uint8_t {
    INVALID,
    FORWARD,
    BACKWARD,
    CALL,
    RETURN,
    MULTIPLE
};

struct BranchInfo {
    uint64_t not_taken_prefix = 0;
    uint64_t taken = 0;
    uint64_t not_taken = 0;
    uint64_t direction_changes;
    uint64_t sequential_taken = 0;
    uint64_t prev_sequential_taken = 0;
    uint64_t sequential_not_taken = 0;
    uint64_t max_sequential_taken = 0;
    uint64_t max_sequential_not_taken = 0;
    std::map<uint64_t, uint64_t> targets;
    bool previous_taken = false;
    bool stable_seq_taken = true;
    bool indirect = false;
    bool repeated = false;
    Direction direction = Direction::INVALID;
};

int main(int argc, char** argv) {
    std::string trace;
    bool verbose = false;
    bool only_taken = false;
    bool only_dynamic = false;
    bool skip_non_user = false;
    uint64_t preceding_branch_pc = 0x0;
    uint64_t all_total = 0;
    uint64_t running_total = 0;

    try {
        processCommandLine(argc, argv, trace, verbose, only_taken, only_dynamic, skip_non_user);
    }
    catch(const trace_tools::CommandLineParser::EarlyExitException& e) {
        std::cerr << e.what() << std::endl;
        return e.getCode();
    }

    stf::STFBranchReader reader(trace, skip_non_user);

    std::map<uint64_t, BranchInfo> branch_counts;
    std::vector<std::pair<uint64_t, BranchInfo>> summary;

    for(const auto& branch: reader) {
        auto& branch_info = branch_counts[branch.getPC()];

        const bool is_taken = branch.isTaken();

        if ((branch_info.taken == 0) && !is_taken) {
            branch_info.not_taken_prefix++;
            //continue;
        }
        
        if (((branch_info.taken + branch_info.not_taken) > 0) && (branch_info.previous_taken != is_taken)) {
            branch_info.direction_changes++;

            if (is_taken) {
                branch_info.sequential_taken     = 1;
                branch_info.max_sequential_taken = (branch_info.max_sequential_taken > 1) ? branch_info.max_sequential_taken : 1;
            }
            else {
                if (branch_info.not_taken) {
                    branch_info.stable_seq_taken = branch_info.stable_seq_taken && (branch_info.sequential_taken == branch_info.prev_sequential_taken);
                    branch_info.prev_sequential_taken = branch_info.sequential_taken;
                }
                branch_info.sequential_not_taken = 1;
                branch_info.max_sequential_not_taken = (branch_info.max_sequential_not_taken > 1) ? branch_info.max_sequential_not_taken : 1;
            }
        }
        else {
            if (is_taken) {
                branch_info.sequential_taken++;
                branch_info.max_sequential_taken = (branch_info.max_sequential_taken > branch_info.sequential_taken) ? branch_info.max_sequential_taken : branch_info.sequential_taken;
            }
            else {
                branch_info.sequential_not_taken++;
                branch_info.max_sequential_not_taken = (branch_info.max_sequential_not_taken > branch_info.sequential_not_taken) ? branch_info.max_sequential_not_taken : branch_info.sequential_not_taken;
            }
        }
        branch_info.taken += is_taken;
        branch_info.not_taken += !is_taken;
        branch_info.previous_taken = is_taken;
        //if (branch_info.not_taken == 0) branch_info.initial_consecutive_takens += is_taken;
        branch_info.targets[branch.getTargetPC()] += is_taken;
        branch_info.indirect = branch.isIndirect();
        branch_info.repeated = (branch.getPC()==preceding_branch_pc);
        preceding_branch_pc  = branch.getPC();

        Direction new_dir = Direction::FORWARD;
        if(branch.isCall()) {
            new_dir = Direction::CALL;
        }
        else if(branch.isReturn()) {
            new_dir = Direction::RETURN;
        }
        else if(branch.isBackwards()) {
            new_dir = Direction::BACKWARD;
        }
        if(branch_info.direction == Direction::INVALID) {
            branch_info.direction = new_dir;
        }
        else if(branch_info.direction != new_dir) {
            stf_assert(branch_info.indirect, "Only indirect branches can have multiple directions");
            branch_info.direction = Direction::MULTIPLE;
        }
        all_total++;
    }


    for (const auto& pair : branch_counts) {
        summary.push_back(pair);
    }
    //auto test = summary[0].second.not_taken;
    //std::cout << "Test before sort: " << test << std::endl;
    std::sort(summary.begin(), summary.end(), [](const auto& a, const auto& b) {
        return ((a.second.taken + a.second.not_taken - a.second.not_taken_prefix) > (b.second.taken + b.second.not_taken - b.second.not_taken_prefix)); 
    });
    //test = summary[0].second.not_taken;
    //std::cout << "Test after sort: " << test << std::endl;
    std::cout << "Total Instances: " << all_total << std::endl;
    uint64_t limit = int(0.98*(double)all_total);
    bool limit_reached = false;

    static constexpr int COLUMN_WIDTH = 17;
    stf::print_utils::printLeft("Rank", 6);
    stf::print_utils::printLeft("Instr PC", COLUMN_WIDTH);
    stf::print_utils::printLeft("Total Instances", COLUMN_WIDTH);
    stf::print_utils::printLeft("Behavior", COLUMN_WIDTH);
    stf::print_utils::printLeft("Direction", COLUMN_WIDTH);
    stf::print_utils::printLeft("Indirect", COLUMN_WIDTH);
    stf::print_utils::printLeft("Repeated", COLUMN_WIDTH);    
    stf::print_utils::printLeft("# Targets", COLUMN_WIDTH);
    stf::print_utils::printLeft("NT Prefix", COLUMN_WIDTH); 
    stf::print_utils::printLeft("Takens", COLUMN_WIDTH);
    stf::print_utils::printLeft("Not Takens", COLUMN_WIDTH);
    stf::print_utils::printLeft("Dir Changes", COLUMN_WIDTH);
    //stf::print_utils::printLeft("Stable Seq Tkns", COLUMN_WIDTH);
    stf::print_utils::printLeft("Max Seq Takens", COLUMN_WIDTH);
    stf::print_utils::printLeft("Max Seq NotTkns", COLUMN_WIDTH);    
    if(verbose) {
        stf::print_utils::printLeft("Target", COLUMN_WIDTH);
        stf::print_utils::printLeft("Traversals", COLUMN_WIDTH);
    }
    std::cout << std::endl;

    uint64_t rank = 0;

    for(const auto& branch: summary) {
        const auto& branch_info = branch.second;
        const auto taken = branch_info.taken;
        const auto not_taken = branch_info.not_taken;


        if(only_dynamic && !(taken && not_taken)) {
            continue;
        }

        if(only_taken && !taken) {
            continue;
        }

        const auto pc = branch.first;
        const auto total = taken + not_taken;
        
        running_total += total;
        if (running_total>limit && !limit_reached) {
            std::cout << "---Limit reached---" << std::endl;
            limit_reached = true;
        }

        stf_assert(total, "Invalid branch behavior for pc " << std::hex << pc);

        stf::print_utils::printDecLeft(++rank, 6);
        stf::print_utils::printHex(pc);
        stf::print_utils::printSpaces(4);
        stf::print_utils::printDecLeft(total, COLUMN_WIDTH);

        if(taken && !not_taken) {
            stf::print_utils::printLeft("AT", COLUMN_WIDTH);
        }
        else if(!taken && not_taken) {
            stf::print_utils::printLeft("NT", COLUMN_WIDTH);
        }
        else if(taken && not_taken) {
            stf::print_utils::printLeft("DYN", COLUMN_WIDTH);
        }

        switch(branch_info.direction) {
            case Direction::FORWARD:
                stf::print_utils::printLeft("Fw->", COLUMN_WIDTH);
                break;
            case Direction::BACKWARD:
                stf::print_utils::printLeft("<-Bk", COLUMN_WIDTH);
                break;
            case Direction::CALL:
                stf::print_utils::printLeft("CALL", COLUMN_WIDTH);
                break;
            case Direction::RETURN:
                stf::print_utils::printLeft("RETURN", COLUMN_WIDTH);
                break;
            case Direction::MULTIPLE:
                stf::print_utils::printLeft("MULTIPLE", COLUMN_WIDTH);
                break;
            case Direction::INVALID:
                stf_throw("Invalid branch direction for pc " << std::hex << pc);
        };

        if(branch_info.indirect) {
            stf::print_utils::printLeft('Y', COLUMN_WIDTH);
        }
        else {
            stf::print_utils::printLeft(" n", COLUMN_WIDTH);
        }
        if(branch_info.repeated) {
            stf::print_utils::printLeft('Y', COLUMN_WIDTH);
        }
        else {
            stf::print_utils::printLeft(" n", COLUMN_WIDTH);
        }

        stf::print_utils::printDecLeft(branch_info.targets.size(), COLUMN_WIDTH);
        stf::print_utils::printDecLeft(branch_info.not_taken_prefix, COLUMN_WIDTH);
        stf::print_utils::printDecLeft(taken, COLUMN_WIDTH);
        stf::print_utils::printDecLeft(not_taken, COLUMN_WIDTH);
        stf::print_utils::printDecLeft(branch_info.direction_changes, COLUMN_WIDTH);
        if (taken && not_taken) {
 /*            if (branch_info.stable_seq_taken) {
                stf::print_utils::printLeft('Y', COLUMN_WIDTH);
            }
            else {
                stf::print_utils::printLeft('n', COLUMN_WIDTH);
            } */
            stf::print_utils::printDecLeft(branch_info.max_sequential_taken, COLUMN_WIDTH);
            stf::print_utils::printDecLeft(branch_info.max_sequential_not_taken, COLUMN_WIDTH);
        }
        else {
            //stf::print_utils::printLeft("-", COLUMN_WIDTH);
            stf::print_utils::printLeft("-", COLUMN_WIDTH);
            stf::print_utils::printLeft("-", COLUMN_WIDTH);
        }

        if(verbose) {
            bool first_line = true;
            for(const auto& target_pair: branch_info.targets) {
                if(STF_EXPECT_FALSE(first_line)) {
                    first_line = false;
                }
                else {
                    stf::print_utils::printSpaces(8*COLUMN_WIDTH);
                }
                stf::print_utils::printHex(target_pair.first);
                stf::print_utils::printSpaces(4);
                stf::print_utils::printDecLeft(target_pair.second);
                std::cout << std::endl;
            }
        }

        std::cout << std::endl;
    }

    return 0;
}
