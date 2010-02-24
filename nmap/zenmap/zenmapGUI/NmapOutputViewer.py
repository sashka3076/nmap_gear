#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                * 
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included COPYING.OpenSSL file, and distribute linked      *
# * combinations including the two. You must obey the GNU GPL in all        *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/

import locale
import sys
import gobject
import gtk
import gtk.gdk
import pango
import re

import zenmapCore.I18N
from zenmapCore.UmitLogging import log
from zenmapCore.UmitConf import NmapOutputHighlight

from zenmapGUI.NmapOutputProperties import NmapOutputProperties

class NmapOutputViewer (gtk.VBox):
    def __init__ (self, refresh=1, stop=1):
        self.nmap_highlight = NmapOutputHighlight()
        gtk.VBox.__init__ (self)
        
        # Creating widgets
        self.__create_widgets()
        
        # Setting scrolled window
        self.__set_scrolled_window()
        
        # Setting text view
        self.__set_text_view()
        
        buffer = self.text_view.get_buffer()
        # The end mark is used to scroll to the bottom of the display.
        self.end_mark = buffer.create_mark(None, buffer.get_end_iter(), False)

        self.refreshing = True
        
        # Adding widgets to the VBox
        self.pack_start(self.scrolled, expand = True, fill = True)
        
        # The NmapCommand instance, if any, whose output is shown in this
        # display.
        self.command_execution = None
        self.nmap_previous_output = ''

    def __create_widgets (self):
        # Creating widgets
        self.scrolled = gtk.ScrolledWindow ()
        self.text_view = gtk.TextView ()
        self.txg_font = gtk.TextTag()
        self.txg_date = gtk.TextTag()
    
    def __set_scrolled_window (self):
        # Seting scrolled window
        self.scrolled.set_border_width (5)
        self.scrolled.add(self.text_view)
        self.scrolled.set_policy (gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)
    
    def __set_text_view(self):
        self.text_view.set_wrap_mode(gtk.WRAP_WORD)
        self.text_view.set_editable(False)
        
        self.txg_output = self.text_view.get_buffer().get_tag_table()
        self.txg_output.add(self.txg_font)
        self.txg_font.set_property("family", "Monospace")
        self.text_view.get_buffer().connect ("changed", self.__text_changed_cb)

    def __text_changed_cb (self, widget):
        buff = self.text_view.get_buffer ()
        buff.apply_tag(self.txg_font, buff.get_start_iter(), buff.get_end_iter())
        self.update_output_colors()
        
    def go_to_host(self, host):
        """Go to host line on nmap output result"""
        buff = self.text_view.get_buffer()
        start_iter, end_iter = buff.get_bounds()

        output = buff.get_text(start_iter, end_iter).split("\n")
        re_host = re.compile("%s\s{0,1}:" % re.escape(host))

        for i in xrange(len(output)):
            if re_host.search(output[i]):
                self.text_view.scroll_to_iter(buff.get_iter_at_line(i), 0, True, 0, 0)
                break
        
    def show_output_properties(self, widget):
        nmap_out_prop = NmapOutputProperties(self.text_view)
        #nmap_out_prop.connect("response", self.update_output_colors)
        
        nmap_out_prop.run()
        
        for prop in nmap_out_prop.property_names:
            widget = nmap_out_prop.property_names[prop][8]

            wid_props = []

            if widget.bold:
                wid_props.append(1)
            else:
                wid_props.append(0)

            if widget.italic:
                wid_props.append(1)
            else:
                wid_props.append(0)

            if widget.underline:
                wid_props.append(1)
            else:
                wid_props.append(0)
 
            wid_props.append("(%s, %s, %s)" % (widget.text_color.red,
                                               widget.text_color.green,
                                               widget.text_color.blue))
            wid_props.append("(%s, %s, %s)" % (widget.highlight_color.red,
                                               widget.highlight_color.green,
                                               widget.highlight_color.blue))

            self.nmap_highlight.__setattr__(widget.property_name, wid_props)
            
        nmap_out_prop.destroy()
        self.nmap_highlight.save_changes()
        self.update_output_colors()

    def update_output_colors(self, dialog=None, response_id=None):
        buff = self.text_view.get_buffer()
        tag_table = buff.get_tag_table()
        start = buff.get_start_iter()
        end = buff.get_end_iter()

        buff.remove_all_tags(start, end)
        buff.apply_tag(self.txg_font, start, end)

        if not self.nmap_highlight.enable:
            return        

        if True:
            properties = ["details",
                          "date",
                          "hostname",
                          "ip",
                          "port_list",
                          "open_port",
                          "closed_port",
                          "filtered_port"]
            
            for pos in xrange(buff.get_line_count()):
                # Grab the current line.
                line_start_iter = buff.get_iter_at_line(pos)
                line_end_iter = line_start_iter.copy()
                if not line_end_iter.ends_line():
                    line_end_iter.forward_to_line_end()
                line = buff.get_text(line_start_iter, line_end_iter)

                if not line:
                    continue
                
                for p in xrange(len(properties)):
                    settings = self.nmap_highlight.__getattribute__(properties[p])
                    match = re.finditer(settings[5], line)

                    # Create tags only if there's a matching for the expression
                    if match:
                        tag = gtk.TextTag()
                        
                        if settings[0]:
                            tag.set_property("weight", pango.WEIGHT_HEAVY)
                        else:
                            tag.set_property("weight", pango.WEIGHT_NORMAL)
                            
                        if settings[1]:
                            tag.set_property("style", pango.STYLE_ITALIC)
                        else:
                            tag.set_property("style", pango.STYLE_NORMAL)
                        
                        if settings[2]:
                            tag.set_property("underline", pango.UNDERLINE_SINGLE)
                        else:
                            tag.set_property("underline", pango.UNDERLINE_NONE)

                        text_color = settings[3]
                        highlight_color = settings[4]

                        tag.set_property("foreground",
gtk.color_selection_palette_to_string([gtk.gdk.Color(*text_color),]))
                        tag.set_property("background",
gtk.color_selection_palette_to_string([gtk.gdk.Color(*highlight_color),]))

                        tag_table.add(tag)
                        tag.set_priority(p)

                    for m in match:
                        try:
                            buff.apply_tag(tag, buff.get_iter_at_line_offset(pos, m.start()),
                                           buff.get_iter_at_line_offset(pos, m.end()))
                        except:
                            pass

    def show_nmap_output(self, output):
        """Show the string (or unicode) output in the output display."""
        self.text_view.get_buffer().set_text(output)
    
    def set_command_execution(self, command):
        """Set the live running command whose output is shown by this display.
        The current output is extracted from the command object."""
        self.command_execution = command
        self.nmap_previous_output = None
        self.refresh_output()

    def refresh_output(self, widget = None):
        """Update the output from the latest output of the command associated
        with this view, as set by set_command_execution. It has no effect if no
        command has been set."""
        log.debug("Refresh nmap output")

        if self.command_execution is None:
            return

        new_output = self.command_execution.get_output()

        v_adj = self.scrolled.get_vadjustment()
        if self.nmap_previous_output != new_output and v_adj is not None:
            # Find out if the view is already scrolled to the bottom.
            at_end = (v_adj.value >= v_adj.upper - v_adj.page_size)

            self.show_nmap_output(new_output)
            self.nmap_previous_output = new_output

            if at_end:
                # If we were already scrolled to the bottom, scroll back to the
                # bottom again. Do it in an idle handler in case the added text
                # causes a scroll bar to appear and reflow the text, making the
                # text a bit taller.
                gobject.idle_add(lambda: self.text_view.scroll_mark_onscreen(self.end_mark))

if __name__ == '__main__':
    w = gtk.Window()
    n = NmapOutputViewer()
    w.add(n)
    w.show_all()
    w.connect('delete-event', lambda x,y,z=None:gtk.main_quit())

    buff = n.text_view.get_buffer()
    buff.set_text(read_file("file_with_encoding_issues.txt"))
    
    gtk.main()
