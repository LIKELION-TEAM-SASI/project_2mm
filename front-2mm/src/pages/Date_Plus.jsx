import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 1rem;
    padding-right: 1rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const Title = styled.div`
  position: relative;
  top: -23px;
  left: 130px;
`;

const SubTitle = styled.div`
  position: relative;
  top: 25px;
  left: 25px;
`;

const NextBtn = styled.div`
  position: relative;
  top: 500px;
  left: 22px;
`;

const Date_Plus = () => {
  return (
    <Container>
      <Back>
        <img src={`${process.env.PUBLIC_URL}/images/backbtn.svg`} />
      </Back>
      <Title>
        <img src={`${process.env.PUBLIC_URL}/images/date_plus.svg`} />
      </Title>
      <SubTitle>
        <img src={`${process.env.PUBLIC_URL}/images/date_select.svg`} />
      </SubTitle>
      <NextBtn>
        <img src={`${process.env.PUBLIC_URL}/images/newbtn.svg`} />
      </NextBtn>
    </Container>
  );
};

export default Date_Plus;
