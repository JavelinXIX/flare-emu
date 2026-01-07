import re

import flare_emu
from ghidralib import *

from pyghidra.script import get_current_interpreter

currentProgram = get_current_interpreter().getCurrentProgram()

class EmuBasicBlock():
    def __init__(self, flowchart, id, start, size, end, succsessors):
        self.start_ea = start
        self.size = size
        self.end_ea = end
        self.succsessors = succsessors
        srlf.type = -1
        self.id = id
        self.flowchart = flowchart

    def succs(self):
      for z in list(
          map(
              lambda x: self.getBlockByAddr(x),
              list(filter(lambda y: y != -1, self.successors)),
          )
      ):
        yield z
  
    def getBlockByAddr(self, addr):
      for bb in self.flowchart:
        if addr >= bb.start_ea and addr < bb.end_ea:
          return bb

class GhidraAnalysisHelper(flare_emu.AnalysisHelper):
    def __init__(self, eh):
        super(GhidraAnalysisHelper, self).__init__()
        self.eh = eh
        lang = currentProgram.getLanguage()
        self.arch = str(lang.getProcessor()).upper()
        self.bitness = lang.getDefaultSpace().getSize()
        filetype = currentProgram.getExecutableFormat()
        if filetype == "Portable Executable (PE)":
            self.filetype = "PE"

    def getFunc(self, addr):
        try:
            func = Function.get(addr)
            return func
        except:
            return None

    def getFuncStart(self, addr):
        func = self.getFunc(addr)
        if func != None:
            return func.entrypoint
        else:
            return None

    def getFuncEnd(self, addr):
        func = self.getFunc(addr)
        if func != None:
            return func.raw.getBody().getMaxAddress().getOffset()
        else:
            return None

    def getFuncName(self, addr, normalized=True):
        if normalized:
            return self.normalizeFuncName(idc.get_func_name(addr))
        else:
            func = self.getFunc(addr)
            if func != None:
                return func.name
            else:
                return None

    def getMnem(self, addr):
        return Instruction(addr).mnemonic

    def _getBlockByAddr(self, addr, flowchart):
        for bb in flowchart:
            if (addr >= bb.start_ea and addr < bb.end_ea) or addr == bb.start_ea:
                return bb
        return None

    # gets address of last instruction in the basic block containing addr
    def getBlockEndInsnAddr(self, addr, flowchart):
        bb = BasicBlock(addr)
        return bb.end_address

    def getMinimumAddr(self):
        return currentProgram.getMemory().getMinAddress().getOffset()

    def getMaximumAddr(self):
        return currentProgram.getMemory().getMaxAddress().getOffset()

    def getBytes(self, addr, size):
        return read_bytes(addr, size)

    def getCString(self, addr):
        return read_cstring(addr)

    def getOperand(self, addr, opndNum):
        return currentProgram.getListing().getInstructionAt(toAddr(addr)).getDefaultOperandRepresentation(opndNum)

    def getWordValue(self, addr):
        return read_u16(addr)

    def getDwordValue(self, addr):
        return read_u32(addr)

    def getQWordValue(self, addr):
        return read_u64(addr)

    #def isThumbMode(self, addr):
    #       return idc.get_sreg(addr, "T") == 1

    def getSegmentName(self, addr):
        return MemoryBlock(addr).name

    def getSegmentStart(self, addr):
        return MemoryBlock(addr).start

    def getSegmentEnd(self, addr):
        return MemoryBlock(addr).end

    def getSegmentDefinedSize(self, addr):
        return MemoryBlock(addr).size

    def getSegments(self):
        segments = MemoryBlock.all()
        segment_addr_list = list(map(lambda segment: segment.start, segments))
        return segment_addr_list

    def getSegmentSize(self, addr):
        return self.getSegmentEnd(addr) - self.getSegmentStart(addr)

    def getSectionName(self, addr):
        return self.getSegmentName(addr)

    def getSectionStart(self, addr):
        return self.getSegmentStart(addr)

    def getSectionEnd(self, addr):
        return self.getSegmentEnd(addr)

    def getSectionSize(self, addr):
        return self.getSegmentSize

    def getSections(self):
        return self.getSegments()

    # gets disassembled instruction with names and comments as a string
    def getDisasmLine(self, addr):
        return Instruction(addr).raw.toString()

    def getName(self, addr):
        return Symbol(addr).name

    def getNameAddr(self, name):
        return Symbol(name).address

    def getOpndType(self, addr, opndNum):
        inst = Instruction(addr)
        return inst.raw.getOperandType(opndNum)

    def getOpndValue(self, addr, opndNum):
        inst = Instruction(addr)
        return inst.operand(opndNum).value

    def makeInsn(self, addr):
        Instruction.create(addr)

    def createFunction(self, addr):
        pass

    def getFlowChart(self, addr):
        func = Function(addr)
        flowchart = []
        id = 0
        for bb in func.basicblocks:
            dest_bbs = bb.destination
            successors = list(map(lambda x: x.start_address, dest_bbs))
            flowchart.append(EmuBasicBlock(
                                flowchart,
                                id,
                                bb.start_address,
                                bb.length,
                                bb.end_address,
                                successors))
            id += 1
        return flowchart

    def getSpDelta(self, addr):
        return 0

    def getXrefsTo(self, addr):
        return Function(addr).xref_addrs

    def getArch(self):
        return self.arch

    def getBitness(self):
        return self.bitness

    def getFileType(self):
        return self.filetype

    def getInsnSize(self, addr):
        return Instruction(addr).length

    def isTerminatingBB(self, bb):
        if len(list(bb.succs())) == 0:
            return True
        return False

    def skipJumpTable(self, addr):
        inst = currentProgram.getListing().getInsrructionAfter(addr)
        return inst.getAddress().getOffset()

    def setName(self, addr, name, size=0):
        Symbol.create(addr, name)

    def setComment(self, addr, comment, repeatable=False):
        setEOLComment(addr, comment)

    def normalizeFuncName(self, funcName):
        # remove appended _n from IDA Pro names
        if funcName.startswith("sub_") or funcName.startswith("loc_"):
            return funcName
        funcName = re.sub(r"_[\d]+$", "", funcName)
        return funcName
