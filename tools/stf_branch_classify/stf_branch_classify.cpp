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
                        bool& skip_non_user,
                        bool& btb_index) {
    trace_tools::CommandLineParser parser("stf_branch_classify");
    parser.addFlag('v', "verbose mode (prints indirect branch targets)");
    parser.addFlag('t', "only report taken branches (branches that are taken at least once)");
    parser.addFlag('d', "only report dynamic branches (branches that are not always-taken or never-taken)");
    parser.addFlag('u', "skip non user-mode instructions");
    parser.addFlag('b', "report 1K BTB index allocations & hits");
    parser.addPositionalArgument("trace", "trace in STF format");
    parser.parseArguments(argc, argv);
    verbose = parser.hasArgument('v');
    only_taken = parser.hasArgument('t');
    only_dynamic = parser.hasArgument('d');
    skip_non_user = parser.hasArgument('u');
    btb_index = parser.hasArgument('b');

    parser.getPositionalArgument(0, trace);
}

enum class Direction : uint8_t {
    INVALID,
    FORWARD,
    BACKWARD,
    MULTIPLE
};

enum class BranchType : uint8_t {
    INVALID,
    CONDITIONAL,
    CALL,
    M_CALL,
    RETURN,
    M_RET,
    JUMP,
    M_JUMP,
    ERROR
};

class BTB {
    struct CacheInfo {
        uint64_t tag = 0;
        uint64_t allocations = 0;
        uint64_t hits = 0;
        bool valid = false;
        std::map<uint64_t,uint64_t> unique_pcs;
    };
    std::array<CacheInfo, 1024> table_;
    uint64_t index_mask_ = (1024-1);
public:
    void access(uint64_t addr) {
        addr >>= 1;
        uint64_t index = addr & index_mask_;
        uint64_t atag  = (addr & ~index_mask_);
        if (!table_[index].valid) {
            table_[index].tag = atag;
            table_[index].allocations++;
            table_[index].valid = true;
        }
        else {
            if (table_[index].tag == atag) table_[index].hits++;
            else {
                table_[index].tag = atag;
                table_[index].allocations++;
                table_[index].valid = true;
            }
        };
        table_[index].unique_pcs[addr]++;
    };
    uint64_t getAllocations(uint64_t index) {
        index &= index_mask_;
        return table_[index].allocations;
    };
    uint64_t getHits(uint64_t index) {
        index &= index_mask_;
        return table_[index].hits;
    };
    uint64_t getNumUniquePCs(uint64_t index) {
        index &= index_mask_;
        return table_[index].unique_pcs.size();
    }; 
};

struct DualCounter {
    uint64_t taken = 0;
    uint64_t not_taken = 0;
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
    uint64_t local_dir_history = 0;
    std::map<uint64_t, uint64_t> targets;
    std::map<uint64_t, uint64_t> precedents;
    std::map<uint64_t, uint64_t> pre_precedents;
    std::map<uint64_t, uint64_t> taken_precedents;
    std::map<uint64_t, uint64_t> indirect_precedents;
    std::map<uint64_t, DualCounter> local_histories;
    std::map<uint64_t, DualCounter> global_dir_histories;
    std::map<uint64_t, DualCounter> cond_dir_histories;
    std::map<uint64_t, DualCounter> global_path_histories;
    bool previous_taken = false;
    bool stable_seq_taken = true;
    bool indirect = false;
    bool repeated = false;
    Direction direction = Direction::INVALID;
    BranchType type = BranchType::INVALID;
};

int main(int argc, char** argv) {
    std::string trace;
    bool verbose = false;
    bool only_taken = false;
    bool only_dynamic = false;
    bool skip_non_user = false;
    bool btb_index = false;
    uint64_t preceding_branch_pc = 0x0;
    uint64_t pre_preceding_branch_pc = 0x0;
    uint64_t preceding_taken_branch_pc = 0x0;
    uint64_t preceding_indirect_branch_pc = 0x0;    
    uint64_t all_total = 0;
    uint64_t all_total_prefix = 0;
    uint64_t running_total = 0;
    BTB btb_all;
    BTB btb_cond;

    try {
        processCommandLine(argc, argv, trace, verbose, only_taken, only_dynamic, skip_non_user, btb_index);
    }
    catch(const trace_tools::CommandLineParser::EarlyExitException& e) {
        std::cerr << e.what() << std::endl;
        return e.getCode();
    }

    stf::STFBranchReader reader(trace, skip_non_user);

    std::map<uint64_t, BranchInfo> branch_counts;
    std::vector<std::pair<uint64_t, BranchInfo>> summary;

    uint64_t global_dir_history = 0;
    uint64_t cond_dir_history = 0;
    uint64_t global_path_history = 0;

    for(const auto& branch: reader) {
        auto& branch_info = branch_counts[branch.getPC()];

        const bool is_taken = branch.isTaken();

        if ((branch_info.taken == 0) && !is_taken) {  // Branch has not yet been taken
            branch_info.not_taken_prefix++;
            all_total_prefix++;
            //continue;
        }
        else {
            btb_all.access(branch.getPC());
            if (!branch.isIndirect()) btb_cond.access(branch.getPC()); 
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
        branch_info.repeated |= (branch.getPC()==preceding_branch_pc);

        branch_info.precedents[preceding_branch_pc]++;
        branch_info.pre_precedents[pre_preceding_branch_pc]++;
        branch_info.taken_precedents[preceding_taken_branch_pc]++;
        branch_info.indirect_precedents[preceding_indirect_branch_pc]++;

        pre_preceding_branch_pc = preceding_branch_pc;
        preceding_branch_pc  = branch.getPC();
        if (is_taken) preceding_taken_branch_pc = branch.getPC();
        if (branch.isIndirect()) preceding_indirect_branch_pc = branch.getPC();

        Direction new_dir = (branch.isBackwards()) ? Direction::BACKWARD : Direction::FORWARD;
        if(branch_info.direction == Direction::INVALID) {
            branch_info.direction = new_dir;
        }
        else if(branch_info.direction != new_dir) {
            stf_assert(branch_info.indirect, "Only multi-target indirect branches can have multiple directions");
            branch_info.direction = Direction::MULTIPLE;
        }

        BranchType new_type = BranchType::CONDITIONAL;
        if(branch.isCall()) {
            new_type = (branch_info.targets.size()>1) ? BranchType::M_CALL : BranchType::CALL;
        }
        else if(branch.isReturn()) {
            new_type = (branch_info.targets.size()>1) ? BranchType::M_RET : BranchType::RETURN;
        }
        else if(branch.isIndirect()) {
            new_type = (branch_info.targets.size()>1) ? BranchType::M_JUMP : BranchType::JUMP;
        }
        
        if( (branch_info.type == BranchType::INVALID)
            || (branch_info.type == BranchType::JUMP)
            || (branch_info.type == BranchType::CALL)
            || (branch_info.type == BranchType::RETURN)) {
            branch_info.type = new_type;
        }
        else if(branch_info.type != new_type) {
            branch_info.type = BranchType::ERROR;
        }

        // This is tracking all histories including those prior to first taken instance
        if (branch_info.type == BranchType::CONDITIONAL) {  
            if (is_taken) {
                branch_info.local_histories[(branch_info.local_dir_history & 65535)].taken++;
                branch_info.global_dir_histories[(global_dir_history & 65535)].taken++;
                branch_info.cond_dir_histories[(cond_dir_history & 65535)].taken++;
                branch_info.global_path_histories[(global_path_history & 65535)].taken++;
            }
            else {
                branch_info.local_histories[(branch_info.local_dir_history & 65535)].not_taken++;
                branch_info.global_dir_histories[(global_dir_history & 65535)].not_taken++;
                branch_info.cond_dir_histories[(cond_dir_history & 65535)].not_taken++;
                branch_info.global_path_histories[(global_path_history & 65535)].not_taken++;
            }
            cond_dir_history = (cond_dir_history<<1) | (is_taken & 0x1);
        }
        branch_info.local_dir_history = (branch_info.local_dir_history<<1) | (is_taken & 0x1);
        global_dir_history = (global_dir_history<<1) | (is_taken & 0x1);
        global_path_history = (global_path_history<<1) ^ (branch.getPC() & 65535);

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
    std::cout << "Total Instances: " << all_total << " Total prefix NTs: " << all_total_prefix << std::endl;
    uint64_t limit = int(0.98*(double)(all_total-all_total_prefix));
    bool limit_reached = false;

    static constexpr int COLUMN_WIDTH = 18;
    stf::print_utils::printLeft("Rank", 6);
    stf::print_utils::printLeft("Instr PC", COLUMN_WIDTH);
    stf::print_utils::printLeft("Type/Behav", 12);
    //stf::print_utils::printLeft("Behavior", 12);
    stf::print_utils::printLeft("PrePrecedes", 12);    
    stf::print_utils::printLeft("Precedents", 12);
    stf::print_utils::printLeft("TknPrecedes", 12);
    stf::print_utils::printLeft("IndPrecedes", 12);
    stf::print_utils::printLeft("Repeated", 12);
    stf::print_utils::printLeft("Targets", 12);
    stf::print_utils::printLeft("MaxDistance", 12);
    stf::print_utils::printLeft("Direction", 12);
    stf::print_utils::printLeft("Total Instances", COLUMN_WIDTH);
    stf::print_utils::printLeft("NT Prefix", 12); 
    stf::print_utils::printLeft("Loc Hists", 12);
    stf::print_utils::printLeft("Loc Hs Mixed", 14);
    stf::print_utils::printLeft("Loc Entropy", COLUMN_WIDTH);
    stf::print_utils::printLeft("Glo Dir Hists", 14);
    stf::print_utils::printLeft("Glo Hs Mixed", 14);
    stf::print_utils::printLeft("Glo Dir Entropy", COLUMN_WIDTH);  
    stf::print_utils::printLeft("Cnd Dir Hists", 14); 
    stf::print_utils::printLeft("Cnd Hs Mixed", 14);
    stf::print_utils::printLeft("Cnd Dir Entropy", COLUMN_WIDTH);
    stf::print_utils::printLeft("Glo Path Hists", 14);
    stf::print_utils::printLeft("Glo PHs Mixed", 14);
    stf::print_utils::printLeft("Glo Path Entropy", COLUMN_WIDTH);  
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

    double max_local_entropy = 0.0;
    double max_glo_dir_entropy = 0.0;
    double max_cond_entropy = 0.0;
    double max_glo_path_entropy = 0.0;

    uint64_t max_local_ent_rank = 0;
    uint64_t max_glo_dir_ent_rank = 0;
    uint64_t max_cond_ent_rank = 0;
    uint64_t max_glo_path_ent_rank = 0;

    uint64_t max_local_ent_pc = 0;
    uint64_t max_glo_dir_ent_pc = 0;
    uint64_t max_cond_ent_pc = 0;
    uint64_t max_glo_path_ent_pc = 0;

    for(const auto& branch: summary) {
        const auto& branch_info = branch.second;
        const auto taken = branch_info.taken;
        const auto not_taken = branch_info.not_taken;
        const auto not_taken_prefix = branch_info.not_taken_prefix;
        const auto not_taken_after_prefix = not_taken - not_taken_prefix;

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

        switch(branch_info.type) {
            case BranchType::CONDITIONAL:
                if (taken && !not_taken) stf::print_utils::printLeft("  CAT", 12);
                else if (taken && not_taken_after_prefix) {
                    if (branch_info.repeated && branch_info.direction==Direction::BACKWARD) 
                        stf::print_utils::printLeft("C1BBL", 12);
                    else  stf::print_utils::printLeft(" CDYN", 12);
                }
                else stf::print_utils::printLeft(" COND", 12);
                break;
            case BranchType::CALL:
                stf::print_utils::printLeft(" Call", 12);
                break;
            case BranchType::M_CALL:
                stf::print_utils::printLeft("M_Call", 12);
                break;
            case BranchType::RETURN:
                stf::print_utils::printLeft(" Ret", 12);
                break;
            case BranchType::M_RET:
                stf::print_utils::printLeft("M_Ret", 12);
                break;
            case BranchType::JUMP:
                stf::print_utils::printLeft(" Jump", 12);
                break;
            case BranchType::M_JUMP:
                stf::print_utils::printLeft("M_Jump", 12);
                break;
            case BranchType::ERROR:
                stf::print_utils::printLeft("ERROR", 12);
                break;
            case BranchType::INVALID:
                stf_throw("Invalid branch direction for pc " << std::hex << pc);
        };
        
        // if(taken && !not_taken) {
        //     if (branch_info.indirect)
        //         stf::print_utils::printLeft("at", 12);
        //     else
        //         stf::print_utils::printLeft("AT", 12);
        // }
        // else if(!taken && not_taken) {
        //     stf::print_utils::printLeft("NT", 12);
        // }
        // else if((taken==1) && not_taken) {
        //     stf::print_utils::printLeft("1_T", 12);
        // }
        // else if(taken && (not_taken_after_prefix==1)) {
        //     stf::print_utils::printLeft("1_NT", 12);
        // }
        // else if(taken && not_taken_after_prefix) {
        //     stf::print_utils::printLeft("DYN", 12);
        // }

        stf::print_utils::printDecLeft(branch_info.pre_precedents.size(), 12);
        stf::print_utils::printDecLeft(branch_info.precedents.size(), 12);
        stf::print_utils::printDecLeft(branch_info.taken_precedents.size(), 12);
        stf::print_utils::printDecLeft(branch_info.indirect_precedents.size(), 12);
        if(branch_info.repeated) {
            if (branch_info.direction==Direction::FORWARD) stf::print_utils::printLeft("Y->", 12);
            else if (branch_info.direction==Direction::BACKWARD) stf::print_utils::printLeft("<-Y", 12);
            else stf::print_utils::printLeft("<Y>", 12);
        }
        else {
            stf::print_utils::printLeft(" n", 12);
        }

        stf::print_utils::printDecLeft(branch_info.targets.size(), 12);

        uint64_t max_distance = 0;
        for (const auto& [target,count] : branch_info.targets) {
            uint64_t distance = std::abs((long long)pc - (long long)target);
            max_distance = (distance > max_distance) ? distance : max_distance;
        }
        if (!branch_info.indirect) {
            stf::print_utils::printSpaces(2);
            stf::print_utils::printHex(max_distance,6);
        }
        else stf::print_utils::printHex(max_distance,8);
        stf::print_utils::printSpaces(2);

        switch(branch_info.direction) {
            case Direction::FORWARD:
                stf::print_utils::printLeft("Fw->", 12);
                break;
            case Direction::BACKWARD:
                stf::print_utils::printLeft("<-Bk", 12);
                break;
            case Direction::MULTIPLE:
                stf::print_utils::printLeft("MULT", 12);
                break;
            case Direction::INVALID:
                stf_throw("Invalid branch direction for pc " << std::hex << pc);
        };

        stf::print_utils::printDecLeft(total, COLUMN_WIDTH);
        stf::print_utils::printDecLeft(branch_info.not_taken_prefix, 12);

        if ((branch_info.type==BranchType::CONDITIONAL) && (taken > 0) && (not_taken > 0)) {
            stf::print_utils::printDecLeft(branch_info.local_histories.size(), 12);
            uint64_t mixed_hists = 0;
            double branch_entropy_sum = 0.0;
            double avg_branch_entropy = 0.0;
            for (const auto& pair : branch_info.local_histories) {

                if ((pair.second.taken > 0) && (pair.second.not_taken > 0)) {
                    mixed_hists++;
                }
                double hist_instances = (double)(pair.second.not_taken + pair.second.taken);
                double prob_taken = (double)pair.second.taken / hist_instances;
                double hist_entropy = prob_taken > 0.5 ? (1 - prob_taken) : prob_taken;   // min(p, 1-p)
                branch_entropy_sum += hist_instances * 2.0 * hist_entropy;
                avg_branch_entropy = branch_entropy_sum/(double)(taken+not_taken);
                if (!limit_reached && (avg_branch_entropy > max_local_entropy)) {
                    max_local_entropy = avg_branch_entropy;
                    max_local_ent_rank = rank;
                    max_local_ent_pc = pc;
                }
            }
            stf::print_utils::printDecLeft(mixed_hists, 14);
            std::cout << std::fixed << std::setprecision(4) << avg_branch_entropy;
            stf::print_utils::printSpaces(COLUMN_WIDTH-6);

            stf::print_utils::printDecLeft(branch_info.global_dir_histories.size(), 14);
            mixed_hists = 0;
            branch_entropy_sum = 0;
            for (const auto& pair : branch_info.global_dir_histories) {

                if ((pair.second.taken > 0) && (pair.second.not_taken > 0)) {
                    mixed_hists++;
                }
                double hist_instances = (double)(pair.second.not_taken + pair.second.taken);
                double prob_taken = (double)pair.second.taken / hist_instances;
                double hist_entropy = prob_taken > 0.5 ? (1 - prob_taken) : prob_taken;   // min(p, 1-p)
                branch_entropy_sum += hist_instances * 2.0 * hist_entropy;
                avg_branch_entropy = branch_entropy_sum/(double)(taken+not_taken);
                if (!limit_reached && (avg_branch_entropy > max_glo_dir_entropy)) {
                    max_glo_dir_entropy = avg_branch_entropy;
                    max_glo_dir_ent_rank = rank;
                    max_glo_dir_ent_pc = pc;
                }

            }
            stf::print_utils::printDecLeft(mixed_hists, 14);
            std::cout << avg_branch_entropy;
            stf::print_utils::printSpaces(COLUMN_WIDTH-6);

            stf::print_utils::printDecLeft(branch_info.cond_dir_histories.size(), 14);
            mixed_hists = 0;
            branch_entropy_sum = 0;
            for (const auto& pair : branch_info.cond_dir_histories) {

                if ((pair.second.taken > 0) && (pair.second.not_taken > 0)) {
                    mixed_hists++;
                }
                double hist_instances = (double)(pair.second.not_taken + pair.second.taken);
                double prob_taken = (double)pair.second.taken / hist_instances;
                double hist_entropy = prob_taken > 0.5 ? (1 - prob_taken) : prob_taken;   // min(p, 1-p)
                branch_entropy_sum += hist_instances * 2.0 * hist_entropy;
                avg_branch_entropy = branch_entropy_sum/(double)(taken+not_taken);
                if (!limit_reached && (avg_branch_entropy > max_cond_entropy)) {
                    max_cond_entropy = avg_branch_entropy;
                    max_cond_ent_rank = rank;
                    max_cond_ent_pc = pc;
                }               
            }
            stf::print_utils::printDecLeft(mixed_hists, 14);
            std::cout << avg_branch_entropy;
            stf::print_utils::printSpaces(COLUMN_WIDTH-6);
            
            stf::print_utils::printDecLeft(branch_info.global_path_histories.size(), 14);
            mixed_hists = 0;
            branch_entropy_sum = 0;
            for (const auto& pair : branch_info.global_path_histories) {

                if ((pair.second.taken > 0) && (pair.second.not_taken > 0)) {
                    mixed_hists++;
                }
                double hist_instances = (double)(pair.second.not_taken + pair.second.taken);
                double prob_taken = (double)pair.second.taken / hist_instances;
                double hist_entropy = prob_taken > 0.5 ? (1 - prob_taken) : prob_taken;   // min(p, 1-p)
                branch_entropy_sum += hist_instances * 2.0 * hist_entropy;
                avg_branch_entropy = branch_entropy_sum/(double)(taken+not_taken);
                if (!limit_reached && (avg_branch_entropy > max_glo_path_entropy)) {
                    max_glo_path_entropy = avg_branch_entropy;
                    max_glo_path_ent_rank = rank;
                    max_glo_path_ent_pc = pc;
                }

            }
            stf::print_utils::printDecLeft(mixed_hists, 14);
            std::cout << avg_branch_entropy;
            stf::print_utils::printSpaces(COLUMN_WIDTH-6);

        }
        else {
            stf::print_utils::printLeft("-", 12);
            stf::print_utils::printLeft("-", 14);
            stf::print_utils::printLeft("-", COLUMN_WIDTH);
            stf::print_utils::printLeft("-", 14);
            stf::print_utils::printLeft("-", 14);
            stf::print_utils::printLeft("-", COLUMN_WIDTH);
            stf::print_utils::printLeft("-", 14);
            stf::print_utils::printLeft("-", 14);
            stf::print_utils::printLeft("-", COLUMN_WIDTH);
            stf::print_utils::printLeft("-", 14);
            stf::print_utils::printLeft("-", 14);
            stf::print_utils::printLeft("-", COLUMN_WIDTH);
        }
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
    
    std::cout << std::endl << "Max Local Entropy: " << max_local_entropy << " Rank : " << max_local_ent_rank << " PC: " << std::hex << max_local_ent_pc;
    std::cout << "  Max Global Entropy: " << max_glo_dir_entropy << std::dec << " Rank : " << max_glo_dir_ent_rank << " PC: " << std::hex << max_glo_dir_ent_pc;
    std::cout << "  Max Conditional Entropy: " << max_cond_entropy << std::dec << " Rank : " << max_cond_ent_rank << " PC: " << std::hex << max_cond_ent_pc;        
    std::cout << "  Max Global Entropy: " << max_glo_path_entropy << std::dec << " Rank : " << max_glo_path_ent_rank << " PC: " << std::hex << max_glo_path_ent_pc << std::endl;

    if(btb_index) {
        std::map<uint64_t, uint64_t> btb_all_unique_hist;
        std::map<uint64_t, uint64_t> btb_cond_unique_hist;        
        std::map<uint64_t, uint64_t> targets;
        uint64_t btb_all_allocs_gt_hits = 0;
        uint64_t btb_cond_allocs_gt_hits = 0;
        std::cout << std::endl;
        stf::print_utils::printLeft("Index", 6);
        stf::print_utils::printLeft("All Allocs", COLUMN_WIDTH);
        stf::print_utils::printSpaces(6);
        stf::print_utils::printLeft("Unique PCs", COLUMN_WIDTH);
        stf::print_utils::printSpaces(6);
        stf::print_utils::printLeft("All Hits", COLUMN_WIDTH);
        stf::print_utils::printSpaces(COLUMN_WIDTH);
        stf::print_utils::printLeft("Cond Allocs", COLUMN_WIDTH);
        stf::print_utils::printSpaces(6);
        stf::print_utils::printLeft("Uniq Cond PCs", COLUMN_WIDTH);
        stf::print_utils::printSpaces(6);
        stf::print_utils::printLeft("Cond Hits", COLUMN_WIDTH);
        std::cout << std::endl;
        for (uint64_t i=0; i<1024; i++) {
            btb_all_unique_hist[btb_all.getNumUniquePCs(i)]++;
            btb_cond_unique_hist[btb_cond.getNumUniquePCs(i)]++;
            stf::print_utils::printDecLeft(i, 6);
            stf::print_utils::printDecLeft(btb_all.getAllocations(i), COLUMN_WIDTH);
            if (btb_all.getAllocations(i)!=0) {
                stf::print_utils::printDecLeft(btb_all.getNumUniquePCs(i), COLUMN_WIDTH);
                if (btb_all.getAllocations(i)>btb_all.getHits(i)) {
                    stf::print_utils::printLeft(">", 6);
                    btb_all_allocs_gt_hits++;
                }
                else stf::print_utils::printSpaces(6);
                stf::print_utils::printDecLeft(btb_all.getHits(i), COLUMN_WIDTH);
                stf::print_utils::printSpaces(COLUMN_WIDTH);
                stf::print_utils::printDecLeft(btb_cond.getAllocations(i), COLUMN_WIDTH);
                if (btb_cond.getAllocations(i)!=0) {
                    stf::print_utils::printDecLeft(btb_cond.getNumUniquePCs(i), COLUMN_WIDTH);
                    if (btb_cond.getAllocations(i)>btb_cond.getHits(i)) {
                        stf::print_utils::printLeft(">", 6);
                        btb_cond_allocs_gt_hits++;
                    }
                    else stf::print_utils::printSpaces(6);
                    stf::print_utils::printDecLeft(btb_cond.getHits(i), COLUMN_WIDTH);
                }
            }
            std::cout << std::endl;
        }
        std::cout << std::endl << "Amount of BTB indices with more allocations than hits" << std::endl;
        stf::print_utils::printLeft("BTB All Branches", 20);
        stf::print_utils::printLeft("BTB Cond Branches", 20);
        std::cout << std::endl;
        stf::print_utils::printDecLeft(btb_all_allocs_gt_hits, 20);
        stf::print_utils::printDecLeft(btb_cond_allocs_gt_hits, 20);
        std::cout << std::endl;
        std::cout << std::endl << "Histogram of unique branch PCs sharing BTB indices" << std::endl;
        stf::print_utils::printLeft("Unique branch PCs per BTB Index", 45);
        stf::print_utils::printLeft("BTB Indices Count", 20);
        std::cout << std::endl;
        for (const auto& pair : btb_all_unique_hist) {
            stf::print_utils::printDecLeft(pair.first, 45);
            stf::print_utils::printDecLeft(pair.second, 20);
            std::cout << std::endl;
        }
        std::cout << std::endl << "Histogram of unique conditional branch PCs sharing BTB indices" << std::endl;
        stf::print_utils::printLeft("Unique conditional branch PCs per BTB Index", 45);
        stf::print_utils::printLeft("BTB Indices Count", 20);
        std::cout << std::endl;
        for (const auto& pair : btb_cond_unique_hist) {
            stf::print_utils::printDecLeft(pair.first, 45);
            stf::print_utils::printDecLeft(pair.second, 20);
            std::cout << std::endl;
        }
        std::cout << std::endl;
    }
    return 0;
}
