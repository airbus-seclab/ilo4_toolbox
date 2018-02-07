#!/usr/bin/ruby
# encoding: ASCII-8bit

require 'metasm'
include Metasm


MOD_DIR = 'mods'


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


