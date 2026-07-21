                                                                         --------------------
                                                                             -- RAVEN --

--This file can detect what channel it is to be able to manage each event type
function normalize_windows_logs(tag, timestamp, record)
    local inserts = record["StringInserts"] -- The record [StringInserts] is being generated in almost all the logs events
    local channel = record["Channel"]
    local source  = record["SourceName"]
    local eventid = record["EventID"]
    local RECORD_PS -- This variable is used to fix any PowerShell log that it's not in the right shape  
    local values_PS_-- This variable will be used to store the values of Customizable PowerShell logs
    local Suspicious = false -- This variable will be used to detect if something not normal

    if inserts == nil then
        return 1, timestamp, record
    end

    -- SECURITY LOGS
    if channel == "Security" then
        if eventid == 4907 then
            -- Event 4907: Auditing settings changed
            record["SecurityID"]       = inserts[1]
            record["AccountName"]      = inserts[2]
            record["AccountDomain"]    = inserts[3]
            record["LogonID"]          = inserts[4]
            record["ObjectServer"]     = inserts[5]
            record["ObjectType"]       = inserts[6]
            record["ObjectName"]       = inserts[7]
            record["HandleID"]         = inserts[8]
            record["OriginalSDDL"]     = inserts[9]
            record["NewSDDL"]          = inserts[10]
            record["ProcessID"]        = inserts[11]
            record["ProcessName"]      = inserts[12]
         -- record["StringInserts"]    = nil
         -- record["Message"]          = nil
        else
            -- Generic Security log fallback
            record["SecurityField1"]   = inserts[1]
            record["SecurityField2"]   = inserts[2]
            record["SecurityField3"]   = inserts[3]
            record["SecurityField4"]   = inserts[4]
            -- record["StringInserts"]    = nil
            -- record["Message"]          = nil
        end

    -- SYSMON LOGS
    elseif source == "Microsoft-Windows-Sysmon" or eventid == 1 or eventid == 3 or eventid == 10 then
        record["Image"]             = inserts[1]
        record["CommandLine"]       = inserts[2]
        record["ParentImage"]       = inserts[3]
        record["User"]              = inserts[4]
        record["IntegrityLevel"]    = inserts[5]




    -------------------------------------------------------=== POWER-SHELL-LOGS-CONF ===---------------------------------------------------
    elseif channel == "Powershell" or source == "PowerShell" then
        record["ProviderName"]  = inserts[1] -- ProviderName is placed at the first could be (Command,Function,Alias,Registery)

        if inserts[2]:match("DetailSequence=") then
          RECORD_PS = inserts[2] -- this means the full record will be on RECORD_PS except Command Part 
         
          record["CommandInfo"] = inserts[3] -- Command part is on the third segment so that it has its own label so it needs its own configuration
          

          
          -- Detect Suspicious PowerShell activity (common malicious patterns) 

            local command_description = record["CommandInfo"]:match(':%s*"(.-)"')
            if command_description ~= nil then 
             record["CommandDescription"] = command_description
            end


        
        else
            record["NewProviderState"] = inserts[2]  -- This means the second segment is providerState (Source-Of-Initiation)
            RECORD_PS = inserts[3]  -- This means the full record will be on third segment even the Command part

          
  
           local command_info = RECORD_PS:match("%-Command%s+(.+)")
           if command_info ~= nil then
            record["CommandInfo"] = command_info
           end
          

             local command_description = RECORD_PS:match(':%s*"(.-)"')
           if command_description ~= nil then 
             record["CommandDescription"] = command_description
           end


        end
        


   -- RECORD_PS is used to contain the whole Powershell record then cut any part without restrictions \\
   -- HostApplication is used to operate on small part of the whole log for ease of use \\
   -- Overall both have the same directions and output at the end -- 




        if RECORD_PS ~= nil then  -- this line to check that RECORD_PS already contain a full log 
          values_PS_ = RECORD_PS
          if values_PS_ ~= nil then
          
            for line in values_PS_:gmatch("[^\r\n]+") do -- Raw-Log splitter
            -- Here we add the hostapplication part and its content that comes in the raw-log into a label/record to operate on its contents 
            -- Some parts will be missed from the beginning of the full-log but it gets handeled using RECORD_PS below 
                if line:match("HostApplication=") then
                    record["HostApplication"] = line:match("HostApplication=(.*)") 
                elseif line:match("HostVersion=") then
                    record["HostVersion"] = line:match("HostVersion=(.*)")
                end
            end
        end
    end
        

        if record["HostApplication"] ~= nil 
        then
            -- Extract PowerShell executable path
            -- Extracting the path of the running instance of powershell 
            local path = record["HostApplication"]:match('^"?(.-%.exe)')
            if path ~= nil then
                record["Path"] = path
            else
                record["Path"] = "N/A"
            end
			
			
			-- Extract any script path update: I have found another part that does the same thing down
--			local weird_script = record["HostApplication"]:match("%-File%s+([%w%p]+%.ps1)")
--			if weird_script then:
--				record[""] = weird_script
--			end
			
            
            -- record["URL"]  = src:match("(https?://[%w%._%-%/%:%?=&%%#+]+)") Extracting URLs associated with process
            local URL = record["HostApplication"]:match("(https?://[%w%._%-%/%:%?=&%%#+]+)")
            if URL ~= nil then
                record["URL"] = URL
            else
                record["URL"] = "No-URLs"
            end

            -- Extracting Security Protocol if there's any online connection
            local sec_protocol = record["HostApplication"]:match("SecurityProtocolType%]::(.-)%s")
            if sec_protocol ~= nil then
                record["SecurityProtocol"] = sec_protocol
            else 
                record["SecurityProtocol"] = "N/A"
            
            end    

            -- Extracting ProgressPreference the behavior action 
            local prog_preference = record["HostApplication"]:match("%$ProgressPreference='(.-)'")
            if prog_preference ~= nil then
                record["ProgressPreference"] = prog_preference
            else 
                record["ProgressPreference"] = "N/A"
            end


            -- Extracting the OutFile (It's the file that was fetched from the internet then downloaded on the local system )
            local out_file = record["HostApplication"]:match("-OutFile%s+'([^']+)'")
            if out_file ~= nil then 
                record["OutFile"]=out_file
            end
           
            
            -- Extracting the excution policy 
            local execution_policy = record["HostApplication"]:match("ExecutionPolicy%s+([%w]+)")
            if execution_policy ~= nil then 
                record["ExecutionPolicy"] = execution_policy
            end

            
            -- Extracting AppTitle (App messages)
            local app_title = record["HostApplication"]:match("-AppTitle%s+(.+)$")
            if app_title ~= nil then
                record["AppTitle"] = app_title
            end

            
            -- Exctracting the -Icon which is the visual identity of the application that behaves (The source of the invocation)
            local app = record["HostApplication"]:match("-Icon%s+([^%s]+)")
            if app ~= nil then 
                record["App"] = app
            end

            
            -- Extracting Powershell scripts if found 
            local ps_script = record["HostApplication"]:match("-File%s+([^%s]+%.ps1)")
            if ps_script ~= nil then 
                record["Script"] = ps_script
            end


            -- Extracting Local Data if the running app provides any GUI response for the triggered script
            local locData = record["HostApplication"]:match("-LocData%s+(.+)%s%-Icon")
            if locData ~= nil then
                record["LocData"] = locData
            end
            

        
        end
   
        
        if RECORD_PS ~= nil then
            values_PS_ = RECORD_PS
           
            -- extract "DetailSequence"
           local detail_sequence = values_PS_:match("DetailSequence%s*=%s*([%d]+)")
            if detail_sequence ~= nil then
              record["DetailSequence"] = detail_sequence
            else
              record["DetailSequence"] = "N/A"
            end
        
            -- extract "UserID"
            local user_id = values_PS_:match("UserId%s*=%s*([ %w_\\]+)") 
            if user_id ~= nil then
               record["UserId"] = user_id
            else
               record["UserId"] = "-"
            end

            -- extract "SequenceNumber"
            local sequence_number = values_PS_:match("SequenceNumber%s*=%s*([%d]+)")
            if sequence_number ~= nil then
                record["SequenceNumber"] = sequence_number
            else 
                record["SequenceNumber"] = "N/A"
            end

            -- extract "ScriptName"
            local script_name = values_PS_:match("ScriptName%s*=%s*([^\r\n]+)")
            if script_name:match("CommandLine=") or script_name:match("CommandPath=") then
                record["ScriptName"] = "N/A"
            else
                record["ScriptName"] = script_name
            end
            

            -- extract "CommandLine" 
            local command_line = values_PS_:match("CommandLine%s*=%s*([^\r\n]+)")
            if command_line ~= nil then
                record["CommandLine"] = command_line
            else
                record["CommandLine"] = "N/A"
            end


            -- extract "PipeLineID"
            local pipeline_id = values_PS_:match("PipelineId%s*=%s*([%d]+)")
            if pipeline_id ~= nil then
                record["PipelineID"] = pipeline_id
            else
                record["PipelineId"] = "N/A"
            end

         
            -- root_reg_path is extracted from RECORD_PS not in the hostapplication as the whole record contains the checking output 
            -- Extracting RootReg, GUID, RegAccessPattern, GroupViewCheck and FinalResult when there's checking on registry values 
            local root_reg_path = values_PS_:match("%$ShellRegRoot%s*=%s*'(.-)'")
            if root_reg_path ~= nil then 
                record["RootRegPath"] = root_reg_path
            end
           

            -- Extracting GUID, Graphical User Interface ID in Windows OS it specify each UI element with a unique ID
            local ui_element_id = values_PS_:match("%$HomeFolderGuid%s*=%s*'(.-)'") 
            if ui_element_id ~= nil then 
                record["GUID"] = ui_element_id
            end


            -- Extracting GUID_NAME Graphical User Interface ID (Name)
            local ui_element_name = values_PS_:match("GUID%s+tail%s+for%s+([%w_%-]+)")
            if ui_element_name ~= nil then 
                record["GUIDName"]= ui_element_name
            end


            -- Extracting BagMRU, Bag Most Recently Used it stores the files and folders user accessed 
            local bag_mru = values_PS_:match("%$bagMRURoot%s*=%s*%$ShellRegRoot%s*%+%s*'(.-)'")
            if bag_mru ~= nil then 
                record["BagMRU"] = bag_mru
            end

            -- Extracting Bags, the properties of the contnet in the viewed folders (sorting, size ... etc )
            local bags = values_PS_:match("%$bagRoot%s*=%s*%$ShellRegRoot%s*%+%s*'(.-)'") 
            if bags ~= nil then 
                record["Bags"] = bags
            end


            -- Extracting function name, sometimes there're functions perform a check on certificates of the settings such as UEFI
            local func = values_PS_:match("function%s+([%w%-_]+)%s*{")
            if func ~= nil then 
                record["Function"] = func
            end 


            -- Extracting any UEFI DB checks 
            local uefi_boot = values_PS_:match("Get%-SecureBootUEFI")
            local uefi_db = values_PS_:match("$UefiDb")
            if uefi_boot or uefi_db then 
                record["UEFI_DB_Read"] = "True"
            end


            -- Extracting Certificate Signature Title 
            local certificate_signature = values_PS_:match("CN=([^,]+),") 
            if certificate_signature ~= nil then 
                record["CertSignature"] = certificate_signature
            end


            -- Extracting Certificate Signature ID 
            local certificate_signature_id = values_PS_:match("%$SignatureTypeGUID%s*[%w_%s%p]*'([%x%-]+)'")
            if certificate_signature_id ~= nil then 
                record["CertificateID"] = certificate_signature_id
            end
            






        end






     
        -- === PowerShell Threat-Aware Normalization ===      
        -- Identify suspicious PowerShell activity (common malicious patterns)
           
        if record["CommandInfo"] ~= nil then
            local cmd  = record["CommandInfo"]:lower()
            if cmd:match("invoke%-expression") or
               cmd:match("invoke") or
               cmd:match("iex") or
               cmd:match("downloadstring") or
               cmd:match("new%-object%s+net%.webclient") or
               cmd:match("invoke%-webrequest") or
               cmd:match("frombase64string") or
               cmd:match("add%-type") or
               cmd:match("invoke%-command") or
               cmd:match("commandinvocation") or
               cmd:match("invoke-webrequest") or
               cmd:match("-WebRequest") or
               cmd:match("commandinvocation%(([^)]+)%)") or
               cmd:match("encodedcommand") then
                Suspicious = true
            end
	
		-- Updated conditions [31/1/2026] just to enrich TDARE and avoid any useless info in addition to make it more smart 

		if record["CommandDescription"] == "Set-Location" or record["CommandDescription"] == "PSConsoleHostReadLine" then
			Suspicious = false
		end
		
		if record["CommandDescription"] == "Set-StrictMode" then
			Suspicious = false
		end
		
		if record["CommandDescription"] == "Out-Default" then
			Suspicious = false
		end
			
		if record["CommandDescription"] == "Clear-EventLog" then
			record["CommandDescription"] = "an attempt to clear event logs by a command execution"
		end	
			
			-- In case if web-request was made by Uri
			
			local Uri 
			
			if cmd:match("invoke-webrequest") or cmd:match("-WebRequest") or cmd:match("invoke%-webrequest") then
				Uri = cmd:match('value%s*=%s*"([^"\r\n]+)"')  
			end 
			
			if Uri then 
			   record["URL"] = Uri
			end
				
		
		end
		-- Updated conditions [31/1/2026] just to enrich TDARE and avoid any useless info in addition to make it more smart 
		if record["ExecutionPolicy"] == "Bypass" and record["Script"] then
			record["CommandDescription"] = "There's a Bypass policy got executed"
		end
		
		
		
		
        -- Add classification and alert level
        record["EventType"] = "PowerShellActivity"
        if Suspicious then
            record["AlertLevel"] = "Suspicious"
        else
            record["AlertLevel"] = "Normal"
        end



        -- Clean up unnecessary verbose data
        record["Details"] = nil

       --------------------------------------------------=== POWERSHELL-CONF-ENDS-HERE ===------------------------------------------






    -- SYSTEM LOGS
    elseif channel == "System" then
        record["SystemField1"]      = inserts[1]
        record["SystemField2"]      = inserts[2]
        record["SystemField3"]      = inserts[3]
    end

    -- Remove the original array to clean the log
    record["StringInserts"] = nil
  
 -- record["HostApplication"] = nil   -- this will be uncommented once finished all development and ready to be launched and if commented then it's furthur developments
    return 1, timestamp, record




end