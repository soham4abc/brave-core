/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

import * as React from 'react'

import { getLocale } from 'brave-ui/helpers'

import checkIcon from './assets/check.svg'
import smileySadIcon from './assets/smiley-sad.svg'

import {
  StyledBorderlessButton,
  StyledButton,
  StyledCaptchaFrame,
  StyledIcon,
  StyledTitle,
  StyledText,
  StyledWrapper
} from './style'

interface Props {
  scheduledCaptchaUrl: string
  attempts: number
}

interface State {
  showInterstitial: 'success' | 'maxAttemptsExceeded' | 'none'
}

export default class AdaptiveCaptcha extends React.PureComponent<Props, State> {
  constructor (props: Props) {
    super(props)
    this.state = {
      showInterstitial: 'none'
    }
  }

  componentDidMount () {
    window.addEventListener('message', (event) => {
      const captchaFrame = document.getElementById('scheduled-captcha') as HTMLIFrameElement
      if (!captchaFrame) {
        return
      }

      const captchaContentWindow = captchaFrame.contentWindow
      if (!event.source || event.source !== captchaContentWindow) {
        return
      }

      if (!event.data) {
        return
      }

      switch (event.data) {
        case 'captcha_ok':
          this.setState({ showInterstitial: 'success' })
          chrome.braveRewards.updateScheduledCaptchaResult(true)
          break
        case 'captcha_failure':
        case 'error':
          chrome.braveRewards.updateScheduledCaptchaResult(false)
          break
      }
    })
  }

  onClose = () => {
    this.setState({ showInterstitial: 'none' })
  }

  onContactSupport = () => {
    this.setState({ showInterstitial: 'none' })
  }

  getScheduledCaptcha = () => {
    const { scheduledCaptchaUrl } = this.props
    return (
      <StyledCaptchaFrame
        id='scheduled-captcha'
        src={scheduledCaptchaUrl}
        sandbox='allow-scripts'
      />
    )
  }

  getMaxAttemptsExceededInterstitial = () => {
    return (
      <StyledWrapper>
        <StyledIcon src={smileySadIcon} />
        <StyledTitle>
          {getLocale('captchaMaxAttemptsExceededTitle')}
        </StyledTitle>
        <StyledText>
          {getLocale('captchaMaxAttemptsExceededText')}
        </StyledText>
        <StyledButton onClick={this.onContactSupport}>
          {getLocale('contactSupport')}
        </StyledButton>
      </StyledWrapper>
    )
  }

  getSuccessInterstitial = () => {
    return (
      <StyledWrapper>
        <StyledIcon src={checkIcon} />
        <StyledTitle textSize='large'>
          {getLocale('captchaSolvedTitle')}
        </StyledTitle>
        <StyledText>
          {getLocale('captchaSolvedText')}
        </StyledText>
        <StyledBorderlessButton onClick={this.onClose}>
          {getLocale('dismiss')}
        </StyledBorderlessButton>
      </StyledWrapper>
    )
  }

  render () {
//    if (this.props.attempts >= 10) {
//      return this.getMaxAttemptsExceededInterstitial()
//    }

    switch (this.state.showInterstitial) {
      case 'success':
        return this.getSuccessInterstitial()
      case 'maxAttemptsExceeded':
        return this.getMaxAttemptsExceededInterstitial()
      case 'none':
        break
    }

    return this.getScheduledCaptcha()
  }
}
