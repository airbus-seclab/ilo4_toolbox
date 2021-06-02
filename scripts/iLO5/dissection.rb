#!/usr/bin/ruby
# encoding: ASCII-8bit

require 'bindata'
require 'metasm'
require 'pathname'

include Metasm


SCRIPT_DIR = 'scripts'
MOD_DIR = 'mods'
LOADER_DIR = 'loaders'
IDA_PATH = 'C:\Program Files\IDA Pro 7.6\ida.exe'


class SectionInfo < BinData::Record
    endian :little
    uint32 :next_ptr
    uint32 :name_ptr
    uint32 :text_base_addr
    uint32 :text_size
    uint32 :dw1
    uint32 :dw2
    stringz :name
end


class BootCoreEntry < BinData::Record
    endian :little
    uint32 :ptr_name
    uint32 :mod_size
    uint32 :mod_id
    uint32 :dw1
    uint32 :dw2
end


class BootInitialEntry < BinData::Record
    endian :little
    uint32 :mod_id
    uint32 :dw1
    uint32 :dw2
    uint32 :dw3
    uint32 :dw4
    uint32 :dw5
    uint32 :dw6
    uint32 :dw7
    uint32 :ptr_initial
    uint32 :ptr_path
    uint32 :dw8
    uint32 :dw9
    uint32 :mod_size
    uint32 :dw10
    uint32 :dw11
    uint32 :dw12
end


class ModName < BinData::Record
    endian :little
    stringz :name
end


class BootHdr < BinData::Record
    endian :little
    uint32 :tasks_count
    uint32 :ptr_task_info_list
    uint32 :size_initial
    uint32 :ptr_initial1
    uint32 :dw3
    uint32 :dw4
    uint32 :dw5
    uint32 :dw6
    uint32 :dw7
    uint32 :ptr_initial2
    uint32 :dw8
    uint32 :dw9
    uint32 :size_list_core
    uint32 :ptr_list_core
end


class TaskInfo < BinData::Record
    endian :little
    uint32 :task_type
    uint32 :virt_space_size
    uint32 :virt_space
    uint32 :dw4
    uint32 :dw5
    uint32 :dw6
    uint32 :dw7
    uint32 :dw8
    uint32 :dw9
    uint32 :dw10
    uint32 :dw11
    uint32 :dw12
    uint32 :dw13
    uint32 :dw14
    uint32 :dw15
    uint32 :dw16
end


class VirtRange < BinData::Record
    endian :little
    uint32 :dw1
    uint32 :dw2
    uint32 :rbase
    uint32 :rsize
    uint32 :mod_id
    uint32 :dw6
    uint32 :dw7
    uint32 :dw8
end


class TaskDef

    attr_accessor :name

    def initialize(name)
        @name = name
        @virt_space = []
    end

    def add_virt_space_entry(entry, base, size, type)
        @virt_space << [entry, base, size, type]
    end

    def gen_loader_script()
        return if @virt_space.size == 0

        script_name = File.join(SCRIPT_DIR, @name + '.py')

        Dir.mkdir(LOADER_DIR) if not Dir.exists? LOADER_DIR
        File.open(File.join(LOADER_DIR, @name + '.bat'), 'wb'){|fd|
            script_path = File.join('..', script_name)
            mod_path = File.join('..', MOD_DIR, ".#{name}.RO")
            fd.puts "\"#{IDA_PATH}\" -A -c -parm -i10000 -b1000 -S\"#{script_path}\" \"#{mod_path}\""
        }

        Dir.mkdir(SCRIPT_DIR) if not Dir.exists? SCRIPT_DIR
        File.open(script_name, 'wb'){|fd|
            fd.puts <<EOS
#!/usr/bin/python
import os
import os.path
import ida_idp

MOD_DIR = 'mods'

segments = [
EOS
        @virt_space[1..-1].each{|entry| fd.puts "    [\"%s\", 0x%x, 0x%x, 0x%x]," % entry}
        fd.puts <<EOS
]

for seg in segments:

    try:
        name, base, size, type = seg
        print("loading segment: %30s 0x%08x 0x%08x 0x%x" % (name, base, size, type))

        # saAbs: Absolute segment
        # scPub: Public. Combine by appending at an offset that meets the alignment requirement
        idc.AddSeg(base, base+size, 0, 1, idaapi.saAbs, idaapi.scPub)

        print("  > new segment created")

        if ".RO" in name:
            idc.set_segm_type(base, idc.SEG_CODE)
            idc.set_segm_attr(base, idc.SEGATTR_PERM, 4 | 1);  #RX
            print("  > SEG_CODE")
        elif ".RW2" in name:
            idc.set_segm_type(base, idc.SEG_BSS)
            idc.set_segm_attr(base, idc.SEGATTR_PERM, 2 | 4);  #RW
            print("  > SEG_BSS")
        else:
            idc.set_segm_type(base, idc.SEG_DATA)
            idc.set_segm_attr(base, idc.SEGATTR_PERM, 2 | 4);  #RW
            print("  > SEG_DATA")

        idc.set_segm_name(base, name)

        mod_path = name

        if os.path.exists(mod_path) and type != 0xC:
            data = open(mod_path, 'rb').read()
            idaapi.put_bytes(base, data)
            plan_and_wait(base, base+size)
            print("  > segment loaded")


    except:
        print(sys.exc_info())
        print("Error with file %s" % name)

plan_and_wait(0, BADADDR)
EOS
        }
    end

end


def list_boottable(elf, sections)
    task_list = [TaskDef.new('Integrity')]
    shared_mod = {}

    boot_sec = elf.sections.find{|sec| sec.name == '.boottable'}
    abort "[x] '.boottable' section not found" if not boot_sec

    enc =  elf.encoded[boot_sec.offset, boot_sec.size]
    hdr = BootHdr.read(enc)


    # parse core list
    puts "\n-----------------[ Shared modules ]-----------------\n\n"

    core_entry_offset = hdr.ptr_list_core - boot_sec.addr

    hdr.size_list_core.times{|i|
        mod = BootCoreEntry.read(enc[core_entry_offset, 0x14])
        core_entry_offset += mod.num_bytes

        modname = ModName.read(enc[mod.ptr_name - boot_sec.addr .. -1]).name
        shared_mod[mod.mod_id] = modname

        puts "> mod 0x%02x - %24s size 0x%08x, id 0x%04x, flags 0x%x,0x%x" % [i, modname, mod.mod_size, mod.mod_id, mod.dw1, mod.dw2]
    }


    # parse task list
    puts "\n-----------------[ Tasks List ]-----------------\n\n"

    task_entry_offset = hdr.ptr_initial1 - boot_sec.addr

    hdr.size_initial.times{
        task = BootInitialEntry.read(enc[task_entry_offset, 0x40])
        task_entry_offset += task.num_bytes

        path = ModName.read(enc[task.ptr_path - boot_sec.addr .. -1]).name
        taskname = Pathname.new(path.gsub("\\","/")).basename
        task_list << TaskDef.new(taskname.to_s)

        puts "> task %02x - path %50s - size 0x%08x" % [task.mod_id, path, task.mod_size]
    }


    # parse virtual memory spaces
    puts "\n-----------------[ Virtual Spaces ]-----------------\n\n"

    task_info_list_offset = hdr.ptr_task_info_list - boot_sec.addr

    hdr.tasks_count.times{|i|
        task_info = TaskInfo.read(enc[task_info_list_offset, 0x40])
        task_info_list_offset += task_info.num_bytes

        puts "> task 0x%02x (%s) - 0x%08x entries" % [i, task_list[i].name, task_info.virt_space_size]

        virt_space_offset = task_info.virt_space - boot_sec.addr

        task_info.virt_space_size.times{
            virt_range = VirtRange.read(enc[virt_space_offset, 0x20])
            virt_space_offset += virt_range.num_bytes

            # resolve virt_range id to a section name
            modinfo = ''
            if virt_range.mod_id != 0xffffffff
                sec_map = sections[virt_range.mod_id-1]

                if sec_map
                    modinfo = "- %s" % sec_map.name
                    task_list[i].add_virt_space_entry(sec_map.name, virt_range.rbase, virt_range.rsize, sec_map.dw1)
                end
            end

            puts "    range: dw1 0x%02x - dw2 0x%03x - base 0x%08x - size 0x%08X - id 0x%08x %s" % [virt_range.dw1, virt_range.dw2, virt_range.rbase, virt_range.rsize, virt_range.mod_id, modinfo]
        }

        # generate an IDA Python script to load the module
        task_list[i].gen_loader_script()
        puts "\n"
    }
end


def list_sections(elf)
    puts "\n-----------------[ Sections List ]-----------------\n\n"

    sections = []
    secinfo= elf.sections.find{|sec| sec.name == '.secinfo'}
    abort('.secinfo section not found') if not secinfo

    puts "> name: #{secinfo.name}, 0x#{secinfo.addr.to_s(16)}, 0x#{secinfo.size.to_s(16)} bytes"
    enc =  elf.encoded[secinfo.offset, secinfo.size]

    sec = SectionInfo.read(enc)
    next_offset = sec.next_ptr - secinfo.addr + secinfo.offset
    sections << sec

    while sec.next_ptr != 0
        sec = SectionInfo.read(elf.encoded[next_offset, 0x80])
        next_offset = sec.next_ptr - secinfo.addr + secinfo.offset
        sections << sec
    end

    sections.each_with_index{|sec, i|
        puts "> 0x%04x - %32s at 0x%08x, size 0x%08x flags 0x%x,0x%x" % [i, sec.name, sec.text_base_addr, sec.text_size, sec.dw1, sec.dw2]
    }

    sections
end


def extract_mods(elf_file)
    puts "> extract from #{elf_file}"
    Dir.mkdir(MOD_DIR) if not Dir.exists? MOD_DIR

    elf = Metasm::ELF.decode_file(elf_file)
    elf.decode_sections
    puts "--"

    elf.sections.each{|sec|
        next if ['NULL', 'NOBITS'].include? sec.type

        puts "  > %28s - type %8s - offset 0x%08x - size 0x%08x bytes" % [sec.name, sec.type, sec.offset, sec.size]
        enc =  elf.encoded[sec.offset, sec.size]

        data = case enc.data
        when Metasm::VirtualFile; enc.data.realstring
        when String; enc.data
        end

        File.open(File.join('mods', sec.name), 'wb'){|fd| fd << data}
    }

    puts "> done\n\n"
end


elf_file = ARGV.shift
abort "[x] usage: #{__FILE__} elf_file" unless elf_file
abort "[x] #{elf_file} not found " unless File.exists? elf_file

extract_mods(elf_file)

elf = Metasm::ELF.decode_file(elf_file)
elf.decode_sections

# get all sections from ELF '.secinfo'
sections = list_sections(elf)

# parse '.boottable'
list_boottable(elf, sections)
