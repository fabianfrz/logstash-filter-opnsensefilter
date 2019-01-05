# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::Opnsensefilter < LogStash::Filters::Base

  config_name "opnsensefilter"

  # Replace the message with this value.
  config :prefix, :validate => :string, :default => ''
  config :field_name, :validate => :string, :default => 'message'


  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    if @field_name
      data = event.get(@field_name).split(",")
      # meta
      event.set("#{@prefix}rule", data[0].to_i)
      event.set("#{@prefix}subrule", data[3].to_i)
      event.set("#{@prefix}input_interface", data[4])
      event.set("#{@prefix}reason", data[5])
      event.set("#{@prefix}action", data[6])
      event.set("#{@prefix}direction_of_traffic", data[7])
      event.set("#{@prefix}ip_version", data[8].to_i)
      if data[8].to_i == 4
        # IPv4
        ip_proto = true
        proto_start = 20
        protocol = data[16]
        event.set("#{@prefix}tos", data[9].to_i(16))
        event.set("#{@prefix}ecn", data[10])
        event.set("#{@prefix}hop_limit", data[11].to_i)
        event.set("#{@prefix}aid", data[12].to_i)
        event.set("#{@prefix}myoffset", data[13].to_i)
        event.set("#{@prefix}flags", data[14])
        event.set("#{@prefix}protocol_id", data[15].to_i)
        event.set("#{@prefix}protocol", data[16])
        event.set("#{@prefix}length", data[17].to_i)
        event.set("#{@prefix}source", data[18])
        event.set("#{@prefix}destination", data[19])
      elsif data[8].to_i == 6
        # IPv6
        ip_proto = true
        proto_start = 17
        protocol = data[12]
        event.set("#{@prefix}klass", data[9].to_i(16))
        event.set("#{@prefix}flow_label", data[10].to_i(16))
        event.set("#{@prefix}hop_limit", data[11].to_i)
        event.set("#{@prefix}protocol", data[12])
        event.set("#{@prefix}protocol_id", data[13].to_i)
        event.set("#{@prefix}length", data[14].to_i)
        event.set("#{@prefix}source", data[15])
        event.set("#{@prefix}destination", data[16])
      end
      if ip_proto
        if protocol.downcase == "tcp" || protocol.downcase == "udp"
          event.set("#{@prefix}spt", data[proto_start].to_i)
          event.set("#{@prefix}dpt", data[proto_start + 1].to_i)
          event.set("#{@prefix}length", data[proto_start + 2].to_i)
        end
        if protocol.downcase == "tcp"
          event.set("#{@prefix}tcp_flags", data[proto_start + 3])
          event.set("#{@prefix}sequence_number", data[proto_start + 4])
          event.set("#{@prefix}ack_number", data[proto_start + 5].to_i)
          event.set("#{@prefix}window", data[proto_start + 6].to_i)
          event.set("#{@prefix}urgent_pointer", data[proto_start + 7])
          event.set("#{@prefix}options", data[proto_start + 8])
        end
      end
    end

    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Opnsensefilter
