#
# $Id$
#
require 'yaml'

module Msf

###
#
# Interface Fingerprinter 
#
# $Revision$
#
# TODO
#
# 2. organize by content length
# 3. regex for URIs
# 4. get params with uri are ignored
# 5. test cases
# 6. 

###
class Plugin::InterfaceFingerprinter < Msf::Plugin

	###
	#
	# This class implements a sample console command dispatcher.
	#
	###
	class ConsoleCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		# The dispatcher's name.
		#
		def name
			"Interface Fingerprinter"
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
				"if_list" => "if_list [--ip ip_address | ID]; List the pages scanned.",
				"if_fingerprint" => "Attempt to fingerprint pages in the database.",
				"if_regex" => "if_regex [REGEX]; Regex to run on bodies and headers.",
				"if_print" => "if_print [ID]; Print information about web page.",
				"if_print_full" => "if_print_full [ID]; Print full page."
			}
		end

		#
		# This method prints out title,length,path for pages available
		#
		def cmd_if_list(*args)
			load_db unless @web_pages
						
			col_names=["id","length", "vhost", "port", "uri", "code", "title"]
			tbl = Rex::Ui::Text::Table.new({
				'Header'  => "Web Pages",
				'Columns' => col_names,
			})
			
			@web_pages.each do |web_page|
				
				body = web_page[:body]
				code = web_page[:code]
				path = web_page[:path]
				vhost = web_page.web_site[:vhost] ? web_page.web_site[:vhost] : web_page.web_site.service.host.address
				port = web_page.web_site[:port] ? web_page.web_site[:port] : web_page.web_site.service.port
				id = web_page["id"]

				if args[0] == "--ip"
					next unless vhost.to_s == args[1].to_s
				end

				# pull title from html
				start = body.split("&lt;title&gt;")[1] if body
				title = start.split("&lt;/title&gt;")[0] if start
								
				title = "UNKNOWN" unless title
				if args.length > 0 and args[0] != "--ip"
					tbl << [id, body.length, vhost, port, path, code, title] if id.to_s == args[0].to_s	
				else 
					tbl << [id, body.length, vhost, port, path, code, title]
				end
			end
			print_line tbl.to_s
		end

		def cmd_if_fingerprint(*args)
			load_db unless @web_pages

			begin
				[
				::Msf::Config.data_directory + File::SEPARATOR + "interface_fingerprints",
				].each do |dir|
					next if not ::File.exist? dir
					::Dir.new(dir).find_all { |e|
						path = dir + File::SEPARATOR + e					
						if ::File.file?(path) and File.readable?(path)
							@config = YAML.load_file(path)
							fingerprinter
						end
					}
				end
			rescue Exception
			end
		end
		
		def cmd_if_regex(*args)
			load_db unless @web_pages
			if args.length < 1
				print_error("No REGEX provided")
				return 
			end

			@web_pages.each do |web_page|
				if check_fingerprint(web_page[:body],args[0]) 
					print_good("Web page id #{web_page[:id]} matches in the body.")
					cmd_if_list(["#{web_page[:id]}"])
				end	
				if check_fingerprint(web_page[:header],args[0])
					print_good("Web page id #{web_page[:id]} matches in the headers.")				
					cmd_if_list(["#{web_page[:id]}"])
				end
			end
		end
		
		def cmd_if_print(*args)
			load_db unless @web_pages
			if args.length < 1
				print_error("No ID provided")
				return 
			end
			cmd_if_list(*args)
		end
		
		def cmd_if_print_full(*args)
			load_db unless @web_pages
			if args.length < 1
				print_error("No ID provided")
				return 
			end
			
			cmd_if_print(*args)
			@web_pages.each do |web_page|
				if web_page["web_site_id"].to_s == args[0].to_s
					print_line "#{web_page[:cookie]}"
					print_line "#{web_page[:headers]}"
					print_line "#{web_page[:body]}"
				end
			end
		end
		
		#
		#
		#
		def load_db(*args)
			# make a request to the db and pull all web requests
			@web_pages = self.framework.db.workspace.web_pages
			
			print_error("Warning, no scanned web_pages found. This plugin isn't of much use without those.") unless @web_pages
		end

		def fingerprinter
			@web_pages.each do |web_page|
				next unless web_page	
				# Check if the response matches in the fingerprint list.
				@config.each do |interface|
					interface['fingerprint_page'].each do |fp|
						# The fingerprint must come from an expected URI. This makes the
						#	fingerprinting process more restrictive but allows the fingerprint regex
						#	to be looser. 
						next unless web_page[:path] == fp
						if(check_fingerprint(web_page[:body],interface['fingerprint']) or check_fingerprint(web_page[:header],interface['fingerprint']))
							# make sure the fingerprint_page matches
							id = web_page["id"]

							vhost = web_page.web_site[:vhost] ? web_page.web_site[:vhost] : web_page.web_site.service.host.address
							port = web_page.web_site[:port] ? web_page.web_site[:port] : web_page.web_site.service.port
						
							print_good("Matching response found, adding a note for #{vhost} : #{interface['title']}")				
	
							self.framework.db.report_note(
								:host => vhost,
								:proto => 'tcp',
								:sname => 'http',
								:port => port,
								:type => 'HTTP_APPLICATION_FINGERPRINT',
								:data => interface['title'],
								:update => :unique_data
							)
							report_instance(web_page,interface['title'])
						end
					end
				end
			end
		end
	
		def check_fingerprint(res,regex)
			# Check the server response against the configuration regex
			pattern = Regexp.new(regex,Regexp::IGNORECASE | Regexp::MULTILINE)

			if (res =~ pattern)
				return true
			end
			return false
		end

		def report_instance(web_page,title)
		end
	end

	#
	# The constructor is called when an instance of the plugin is created.  The
	# framework instance that the plugin is being associated with is passed in
	# the framework parameter.  Plugins should call the parent constructor when
	# inheriting from Msf::Plugin to ensure that the framework attribute on
	# their instance gets set.
	#
	def initialize(framework, opts)
		super

		# If this plugin is being loaded in the context of a console application
		# that uses the framework's console user interface driver, register
		# console dispatcher commands.
		add_console_dispatcher(ConsoleCommandDispatcher)

		print_status("Interface Fingerprinter plugin loaded.")
	end

	def cleanup
		remove_console_dispatcher('interface_fingerprinter')
	end


	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"Interface Fingerprinter"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Useful for analyzing scanned web sites later."
	end

protected	
end
end
