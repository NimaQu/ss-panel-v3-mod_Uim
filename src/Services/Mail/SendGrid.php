<?php

namespace App\Services\Mail;

use App\Services\Config;
use SendGrid\Attachment;
use SendGrid\Content;
use SendGrid\Email;
use SendGrid\Mail;

class SendGrid extends Base
{
    private $config;
    private $sg;
    private $sender;
    private $sendername;

    public function __construct()
    {
        $this->config = $this->getConfig();
        $this->sg = new \SendGrid($this->config['key']);
        $this->sender = $this->config['sender'];
        $this->name = $this->config['name'];
    }

    public function getConfig()
    {
        return [
            'key' => Config::get('sendgrid_key'),
            'sender' => Config::get('sendgrid_sender')
            'name' => Config::get('sendgrid_name')
        ];
    }

    public function send($to_address, $subject_raw, $text, $files)
    {
        $from = new Email($this->sendername, $this->sender);
        $subject = $subject_raw;
        $to = new Email(null, $to_address);
        $content = new Content('text/html', $text);
        $mail = new Mail($from, $subject, $to, $content);

        foreach ($files as $file) {
            $attachment = new Attachment();
            $attachment->setContent(base64_encode(file_get_contents($file)));
            $attachment->setType('application/octet-stream');
            $attachment->setFilename(basename($file));
            $attachment->setDisposition('attachment');
            $attachment->setContentId('backup');
            $mail->addAttachment($attachment);
        }

        $response = $this->sg->client->mail()->send()->post($mail);
        echo $response->body();
    }
}
