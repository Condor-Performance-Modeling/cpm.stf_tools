#include <cstdlib>

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <queue>

#include "command_line_parser.hpp"
#include "file_utils.hpp"
#include "stf_record_types.hpp"
#include "stf_reader.hpp"
#include "stf_writer.hpp"
#include "tools_util.hpp"
#include "stf_decoder.hpp"
#include "stf_inst.hpp"

class SourceRegInferringSTFReader : public stf::STFReader {

   public:
   inline stf::STFReaderBase& operator>>(stf::STFRecord::UniqueHandle& rec) {
      std::cerr << "I'm all up in your stf readers now" << std::endl;
      stf::STFReader::operator>>(rec);
      return *this;
   }

   SourceRegInferringSTFReader(const std::string_view filename, const bool force_single_threaded_stream=false) :
       stf::STFReader(filename, force_single_threaded_stream) {}
};

static void parseCommandLine(int argc,
                             char** argv,
                             std::string& infile,
                             std::string& outfile,
                             bool& overwrite
                             ) {
    overwrite = false;

    trace_tools::CommandLineParser parser("stf_infer_src_regs");
    parser.addFlag('f', "Overwrite existing file");
    parser.addPositionalArgument("infile", "STF to which to add inferred source register records");
    parser.addPositionalArgument("outfile", "Output STF file");
    parser.parseArguments(argc, argv);

    overwrite = parser.hasArgument('f');

    parser.getPositionalArgument(0, infile);
    parser.getPositionalArgument(1, outfile);
}

int main(int argc, char* argv[]) {
    bool overwrite = false;
    std::string infile;
    std::string outfile;

    try {
        parseCommandLine(argc, argv, infile, outfile, overwrite);
    }
    catch(const trace_tools::CommandLineParser::EarlyExitException& e) {
        std::cerr << e.what() << std::endl;
        return e.getCode();
    }

    OutputFileManager outfile_man(overwrite);

    try {
        outfile_man.open(infile, outfile);
    }
    catch(const OutputFileManager::FileExistsException& e) {
        std::cerr << e.what() << std::endl << "Specify -f if you want to overwrite." << std::endl;
        return 1;
    }

    SourceRegInferringSTFReader reader(infile);
    stf::STFWriter writer(outfile_man.getOutputName());

    stf::STFDecoder mavis_decoder(reader.getInitialIEM());
    std::unique_ptr<stf::STFRegState> reg_state = std::make_unique<stf::STFRegState>(reader.getISA(), reader.getInitialIEM());

    reader.copyHeader(writer);
    writer.finalizeHeader();

    try {
        stf::STFRecord::UniqueHandle r;
        std::vector<stf::InstRegRecord> instr_reg_records;
        while(reader) {
            reader >> r;

            if  ((r->getId() == stf::descriptors::internal::Descriptor::STF_INST_REG) &&
                 (r->as<stf::InstRegRecord>().getOperandType() == stf::Registers::STF_REG_OPERAND_TYPE::REG_STATE)) {

                reg_state->regStateUpdate(r->as<stf::InstRegRecord>());

                writer << *r;
            } else if ((r->getId() == stf::descriptors::internal::Descriptor::STF_INST_REG) &&
                       (r->as<stf::InstRegRecord>().getOperandType() == stf::Registers::STF_REG_OPERAND_TYPE::REG_DEST)) {

                instr_reg_records.emplace_back(r->as<stf::InstRegRecord>());

            } else if ( r->isInstructionRecord() ) {
                uint32_t opcode;
                if (r->getId() == stf::descriptors::internal::Descriptor::STF_INST_OPCODE16) {
                    opcode = r->as<stf::InstOpcode16Record>().getOpcode();
                } else {
                    opcode = r->as<stf::InstOpcode32Record>().getOpcode();
                }

                mavis_decoder.decode(opcode);
                std::vector<stf::InstRegRecord> operands(mavis_decoder.getRegisterOperands());

                for (auto& opr : operands) {
                    if (opr.getOperandType() == stf::Registers::STF_REG_OPERAND_TYPE::REG_SOURCE) {
                        // FIXME handle both scalar and vector dtype
                        stf::InstRegRecord new_source_record(
                            opr.getReg(),
                            opr.getOperandType(),
                            reg_state->getRegScalarValue(opr.getReg())
                        );

                        writer << new_source_record;
                    }
                }

                for (auto& r : instr_reg_records) {
                    // FIXME check for register existence without generating an exception
                    try {
                        reg_state->regStateUpdate(r);
                    } catch (const stf::STFRegState::RegNotFoundException& e) {
                        continue;
                    }
                    writer << r;
                }

                writer << *r;
                instr_reg_records.clear();
            }
        }
    }
    catch(const stf::EOFException&) {
    }

    reader.close();
    writer.close();

    outfile_man.setSuccess();

    return 0;
}
